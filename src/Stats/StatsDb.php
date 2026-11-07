<?php

namespace SimpleSAML\Module\clave\Stats;

/**
 * Clave bridge usage statistics.
 *
 * Aggregates the raw events written by SimpleSAMLphp's statistics output
 * (statistics.out core:File: one file per UTC day, "YYYY-MM-DD.log", one
 * JSON event per line) into small per-year SQLite databases
 * ("stats-YYYY.sqlite"), so the raw files can be removed after a short
 * period. Complete past years are closed and packed (a compressed copy to
 * archive elsewhere); databases are NEVER deleted by this code.
 *
 * Aggregates per day:
 *   dia_sp      day x SP x protocol: attempts, successes, cancellations,
 *               failures, distinct sessions
 *   dia_metodo  day x Cl@ve method (issuer of Cl@ve's response): successes,
 *               errors, time spent in Cl@ve (p50/p95)
 *   dia_hora    day x hour (UTC): attempts, successes
 *   dia_estado  day x SP x error status (Code/SubCode)
 *   dia_compat  day: the counters of the legacy stats pages
 *   catalogo    day x SP registered in the metadata (daily snapshot)
 *   procesados  processed days (re-processing a day replaces its rows)
 *
 * Definitions:
 *   attempt      saml:idp:AuthnRequest / clave:idp:AuthnRequest
 *   success      saml:idp:Response / clave:idp:Response
 *   cancellation saml:idp:Response:error with SubCode AuthnFailed or
 *                RequestDenied (what Cl@ve returns on cancel / failed auth)
 *   failure      any other saml:idp:Response:error
 *
 * Written for PHP >= 7.2 and without SimpleSAMLphp dependencies, so the
 * same code can aggregate history on old hosts (see export/import, which do
 * not need SQLite).
 */
class StatsDb
{
    const SCHEMA_VERSION = '1';

    /** @var string */
    private $dir;

    /** @var array<int,\PDO> */
    private $dbs = array();

    public function __construct($dir)
    {
        $this->dir = rtrim($dir, '/');
    }

    public function getDir()
    {
        return $this->dir;
    }

    /**
     * Inside SimpleSAMLphp: [database dir, raw dir] from its configuration.
     *   database dir: 'clave.stats.dbdir', or <datadir>/clave-stats
     *   raw dir:      'directory' of the core:File statistics output (or null)
     */
    public static function sspPaths()
    {
        $c = \SimpleSAML\Configuration::getInstance();
        $raw = null;
        foreach ($c->getOptionalArray('statistics.out', array()) as $out) {
            if (is_array($out) && isset($out['class']) && $out['class'] === 'core:File' && !empty($out['directory'])) {
                $raw = rtrim($c->resolvePath($out['directory']), '/');
            }
        }
        $db = $c->getOptionalString('clave.stats.dbdir', null);
        if ($db === null || $db === '') {
            $db = rtrim($c->resolvePath($c->getOptionalString('datadir', 'data/')), '/') . '/clave-stats';
        }
        return array(rtrim($db, '/'), $raw);
    }

    /* =====================================================================
     *  Raw files
     * ===================================================================== */

    /**
     * Raw file of a day in $rawDir: "YYYY-MM-DD.log" or ".log.gz" (null if none).
     */
    public static function rawFile($rawDir, $day)
    {
        foreach (array('.log', '.log.gz') as $ext) {
            $f = rtrim($rawDir, '/') . '/' . $day . $ext;
            if (is_file($f)) {
                return $f;
            }
        }
        return null;
    }

    /**
     * Days with a raw file in $rawDir, sorted.
     * @return array<string,string> day => file
     */
    public static function rawDays($rawDir)
    {
        $out = array();
        foreach ((array)glob(rtrim($rawDir, '/') . '/*.log*') as $f) {
            if (preg_match('/^(\d{4}-\d{2}-\d{2})\.log(\.gz)?$/', basename($f), $m)) {
                // if both exist, prefer the uncompressed one (still being written)
                if (!isset($out[$m[1]]) || empty($m[2])) {
                    $out[$m[1]] = $f;
                }
            }
        }
        ksort($out);
        return $out;
    }

    /**
     * Aggregate one raw file (one UTC day). Pure: no database needed.
     *
     * @return array {dia, lineas, invalidas, sha256, sp:[], metodo:[], hora:[], estado:[], compat:[]}
     */
    public static function aggregateFile($file, $day = null)
    {
        if ($day === null) {
            if (!preg_match('/(\d{4}-\d{2}-\d{2})\.log(\.gz)?$/', $file, $m)) {
                throw new \RuntimeException("Cannot tell the day of $file (expected YYYY-MM-DD.log[.gz])");
            }
            $day = $m[1];
        }
        $h = (substr($file, -3) === '.gz') ? gzopen($file, 'rb') : fopen($file, 'rb');
        if ($h === false) {
            throw new \RuntimeException("Cannot open $file");
        }
        $agg = self::newAggregate($day);
        $ctx = hash_init('sha256');
        $sessions = array();
        $times = array();
        $isGz = (substr($file, -3) === '.gz');
        while (true) {
            $line = $isGz ? gzgets($h) : fgets($h);
            if ($line === false) {
                break;
            }
            hash_update($ctx, $line);
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $agg['lineas']++;
            $p = strpos($line, '{');
            $ev = ($p === false) ? null : json_decode(substr($line, $p), true);
            if (!is_array($ev) || !isset($ev['op'])) {
                $agg['invalidas']++;
                continue;
            }
            self::addEvent($agg, $ev, $sessions, $times);
        }
        $isGz ? gzclose($h) : fclose($h);
        $agg['sha256'] = hash_final($ctx);
        self::finishAggregate($agg, $sessions, $times);
        return $agg;
    }

    private static function newAggregate($day)
    {
        return array(
            'dia' => $day, 'lineas' => 0, 'invalidas' => 0, 'sha256' => '',
            'sp' => array(), 'metodo' => array(), 'hora' => array(), 'estado' => array(),
            'compat' => array('total_requests' => 0, 'total_responses' => 0,
                              'saml_requests' => 0, 'eidas_requests' => 0, 'stork_requests' => 0),
        );
    }

    private static function &spRow(array &$agg, $sp, $proto)
    {
        $k = $sp . "\t" . $proto;
        if (!isset($agg['sp'][$k])) {
            $agg['sp'][$k] = array('sp' => $sp, 'protocolo' => $proto, 'intentos' => 0, 'exitos' => 0,
                                   'cancelaciones' => 0, 'fallos' => 0, 'sesiones' => 0);
        }
        return $agg['sp'][$k];
    }

    private static function addEvent(array &$agg, array $ev, array &$sessions, array &$times)
    {
        $op = (string)$ev['op'];
        $sp = isset($ev['spEntityID']) ? (string)$ev['spEntityID'] : '';
        $proto = isset($ev['protocol']) ? (string)$ev['protocol'] : '';
        $hour = isset($ev['time']) ? (int)gmdate('G', (int)$ev['time']) : null;

        switch ($op) {
            case 'saml:idp:AuthnRequest':
            case 'clave:idp:AuthnRequest':
                $r = &self::spRow($agg, $sp, $proto);
                $r['intentos']++;
                if (isset($ev['_id'])) {
                    $sessions[$sp . "\t" . $proto][(string)$ev['_id']] = true;
                }
                unset($r);
                self::hourAdd($agg, $hour, 'intentos');
                // legacy counters (accumulative.php)
                $agg['compat']['total_requests']++;
                if ($proto === 'saml2') {
                    $agg['compat']['saml_requests']++;
                } elseif ($proto === 'saml2-eidas') {
                    $agg['compat']['eidas_requests']++;
                } elseif ($proto === 'saml2-stork') {
                    $agg['compat']['stork_requests']++;
                }
                break;

            case 'saml:idp:Response':
            case 'clave:idp:Response':
                $r = &self::spRow($agg, $sp, $proto);
                $r['exitos']++;
                unset($r);
                self::hourAdd($agg, $hour, 'exitos');
                break;

            case 'saml:idp:Response:error':
                $code = self::statusName(isset($ev['error']['Code']) ? $ev['error']['Code'] : '');
                $sub = self::statusName(isset($ev['error']['SubCode']) ? $ev['error']['SubCode'] : '');
                $r = &self::spRow($agg, $sp, $proto);
                if ($sub === 'AuthnFailed' || $sub === 'RequestDenied') {
                    $r['cancelaciones']++;
                } else {
                    $r['fallos']++;
                }
                unset($r);
                $st = $code . ($sub !== '' ? '/' . $sub : '');
                $k = $sp . "\t" . $st;
                if (!isset($agg['estado'][$k])) {
                    $agg['estado'][$k] = array('sp' => $sp, 'estado' => $st, 'n' => 0);
                }
                $agg['estado'][$k]['n']++;
                break;

            case 'clave:sp:Response':
            case 'clave:sp:Response:error':
                $m = isset($ev['idpEntityID']) ? (string)$ev['idpEntityID'] : '';
                if (!isset($agg['metodo'][$m])) {
                    $agg['metodo'][$m] = array('metodo' => $m, 'exitos' => 0, 'errores' => 0,
                                               't_n' => 0, 't_p50' => null, 't_p95' => null);
                }
                if ($op === 'clave:sp:Response') {
                    $agg['metodo'][$m]['exitos']++;
                    $agg['compat']['total_responses']++;
                    if (isset($ev['logintime']) && is_numeric($ev['logintime'])) {
                        $times[$m][] = (float)$ev['logintime'];
                    }
                } else {
                    $agg['metodo'][$m]['errores']++;
                }
                break;
        }
    }

    private static function hourAdd(array &$agg, $hour, $field)
    {
        if ($hour === null) {
            return;
        }
        if (!isset($agg['hora'][$hour])) {
            $agg['hora'][$hour] = array('hora' => $hour, 'intentos' => 0, 'exitos' => 0);
        }
        $agg['hora'][$hour][$field]++;
    }

    /** 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed' -> 'AuthnFailed' */
    private static function statusName($urn)
    {
        $urn = is_string($urn) ? $urn : '';
        $p = strrpos($urn, ':');
        return $p === false ? $urn : substr($urn, $p + 1);
    }

    private static function finishAggregate(array &$agg, array $sessions, array $times)
    {
        foreach ($sessions as $k => $ids) {
            if (isset($agg['sp'][$k])) {
                $agg['sp'][$k]['sesiones'] = count($ids);
            }
        }
        foreach ($times as $m => $t) {
            sort($t);
            $n = count($t);
            $agg['metodo'][$m]['t_n'] = $n;
            $agg['metodo'][$m]['t_p50'] = round($t[(int)floor(0.50 * ($n - 1))], 2);
            $agg['metodo'][$m]['t_p95'] = round($t[(int)floor(0.95 * ($n - 1))], 2);
        }
        ksort($agg['hora']);
        $agg['sp'] = array_values($agg['sp']);
        $agg['metodo'] = array_values($agg['metodo']);
        $agg['hora'] = array_values($agg['hora']);
        $agg['estado'] = array_values($agg['estado']);
    }

    /* =====================================================================
     *  Yearly databases
     * ===================================================================== */

    public function dbFile($year)
    {
        return $this->dir . '/stats-' . (int)$year . '.sqlite';
    }

    /** Years with a database in the directory, sorted. */
    public function years()
    {
        $y = array();
        foreach ((array)glob($this->dir . '/stats-*.sqlite') as $f) {
            if (preg_match('/stats-(\d{4})\.sqlite$/', $f, $m)) {
                $y[] = (int)$m[1];
            }
        }
        sort($y);
        return $y;
    }

    /**
     * Database of a year. $write: create it if missing and open read-write.
     * @return \PDO|null  null if read-only and it does not exist
     */
    public function db($year, $write = false)
    {
        $year = (int)$year;
        if (isset($this->dbs[$year])) {
            return $this->dbs[$year];
        }
        $f = $this->dbFile($year);
        if (!$write && !is_file($f)) {
            return null;
        }
        if (!class_exists('PDO') || !in_array('sqlite', \PDO::getAvailableDrivers(), true)) {
            throw new \RuntimeException('PHP has no pdo_sqlite: use "exportar" here and "importar" on a host that has it.');
        }
        if ($write && !is_dir($this->dir)) {
            mkdir($this->dir, 0750, true);
        }
        $dsn = 'sqlite:' . $f;
        $pdo = new \PDO($dsn, null, null, array(\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION));
        $pdo->exec('PRAGMA busy_timeout = 5000');
        if ($write) {
            $this->createSchema($pdo, $year);
        }
        $this->dbs[$year] = $pdo;
        return $pdo;
    }

    private function createSchema(\PDO $db, $year)
    {
        $db->exec('
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS dia_sp (dia TEXT, sp TEXT, protocolo TEXT,
                intentos INTEGER, exitos INTEGER, cancelaciones INTEGER, fallos INTEGER, sesiones INTEGER,
                PRIMARY KEY (dia, sp, protocolo));
            CREATE TABLE IF NOT EXISTS dia_metodo (dia TEXT, metodo TEXT, exitos INTEGER, errores INTEGER,
                t_n INTEGER, t_p50 REAL, t_p95 REAL, PRIMARY KEY (dia, metodo));
            CREATE TABLE IF NOT EXISTS dia_hora (dia TEXT, hora INTEGER, intentos INTEGER, exitos INTEGER,
                PRIMARY KEY (dia, hora));
            CREATE TABLE IF NOT EXISTS dia_estado (dia TEXT, sp TEXT, estado TEXT, n INTEGER,
                PRIMARY KEY (dia, sp, estado));
            CREATE TABLE IF NOT EXISTS dia_compat (dia TEXT PRIMARY KEY, total_requests INTEGER,
                total_responses INTEGER, saml_requests INTEGER, eidas_requests INTEGER, stork_requests INTEGER);
            CREATE TABLE IF NOT EXISTS catalogo (dia TEXT, sp TEXT, nombre TEXT, institucion TEXT,
                PRIMARY KEY (dia, sp));
            CREATE TABLE IF NOT EXISTS procesados (dia TEXT PRIMARY KEY, fichero TEXT, lineas INTEGER,
                invalidas INTEGER, sha256 TEXT, procesado_en TEXT);
        ');
        $st = $db->prepare('INSERT OR IGNORE INTO meta (k, v) VALUES (?, ?)');
        $st->execute(array('schema_version', self::SCHEMA_VERSION));
        $st->execute(array('anio', (string)$year));
        $st->execute(array('creado', gmdate('c')));
    }

    public function meta($year, $key)
    {
        $db = $this->db($year);
        if ($db === null) {
            return null;
        }
        $st = $db->prepare('SELECT v FROM meta WHERE k = ?');
        $st->execute(array($key));
        $v = $st->fetchColumn();
        return $v === false ? null : $v;
    }

    public function setMeta($year, $key, $value)
    {
        $db = $this->db($year, true);
        $st = $db->prepare('INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)');
        $st->execute(array($key, $value));
    }

    public function isClosed($year)
    {
        return $this->meta($year, 'cerrado') !== null;
    }

    /**
     * Store the aggregate of one day (replaces whatever that day had).
     * Refuses to write into a closed year unless $force.
     */
    public function storeDay(array $agg, $file = '', $force = false)
    {
        $year = (int)substr($agg['dia'], 0, 4);
        if (!$force && is_file($this->dbFile($year)) && $this->isClosed($year)) {
            throw new \RuntimeException("Year $year is closed: not writing day {$agg['dia']} (use --forzar).");
        }
        $db = $this->db($year, true);
        $d = $agg['dia'];
        $db->beginTransaction();
        try {
            foreach (array('dia_sp', 'dia_metodo', 'dia_hora', 'dia_estado', 'dia_compat', 'procesados') as $t) {
                $db->prepare("DELETE FROM $t WHERE dia = ?")->execute(array($d));
            }
            $st = $db->prepare('INSERT INTO dia_sp VALUES (?,?,?,?,?,?,?,?)');
            foreach ($agg['sp'] as $r) {
                $st->execute(array($d, $r['sp'], $r['protocolo'], $r['intentos'], $r['exitos'],
                                   $r['cancelaciones'], $r['fallos'], $r['sesiones']));
            }
            $st = $db->prepare('INSERT INTO dia_metodo VALUES (?,?,?,?,?,?,?)');
            foreach ($agg['metodo'] as $r) {
                $st->execute(array($d, $r['metodo'], $r['exitos'], $r['errores'], $r['t_n'], $r['t_p50'], $r['t_p95']));
            }
            $st = $db->prepare('INSERT INTO dia_hora VALUES (?,?,?,?)');
            foreach ($agg['hora'] as $r) {
                $st->execute(array($d, $r['hora'], $r['intentos'], $r['exitos']));
            }
            $st = $db->prepare('INSERT INTO dia_estado VALUES (?,?,?,?)');
            foreach ($agg['estado'] as $r) {
                $st->execute(array($d, $r['sp'], $r['estado'], $r['n']));
            }
            $c = $agg['compat'];
            $db->prepare('INSERT INTO dia_compat VALUES (?,?,?,?,?,?)')->execute(array($d,
                $c['total_requests'], $c['total_responses'], $c['saml_requests'], $c['eidas_requests'], $c['stork_requests']));
            $db->prepare('INSERT INTO procesados VALUES (?,?,?,?,?,?)')->execute(array($d, basename($file),
                $agg['lineas'], $agg['invalidas'], $agg['sha256'], gmdate('c')));
            $db->commit();
        } catch (\Exception $e) {
            $db->rollBack();
            throw $e;
        }
    }

    /** Store a catalogue snapshot: list of [sp, nombre, institucion]. */
    public function storeCatalog($day, array $rows)
    {
        $db = $this->db((int)substr($day, 0, 4), true);
        $db->beginTransaction();
        $db->prepare('DELETE FROM catalogo WHERE dia = ?')->execute(array($day));
        $st = $db->prepare('INSERT OR REPLACE INTO catalogo VALUES (?,?,?,?)');
        foreach ($rows as $r) {
            $st->execute(array($day, $r[0], $r[1], $r[2]));
        }
        $db->commit();
    }

    public function isProcessed($day)
    {
        $db = $this->db((int)substr($day, 0, 4));
        if ($db === null) {
            return false;
        }
        $st = $db->prepare('SELECT 1 FROM procesados WHERE dia = ?');
        $st->execute(array($day));
        return $st->fetchColumn() !== false;
    }

    /** Processed days of a year => sha256 */
    public function processedDays($year)
    {
        $db = $this->db($year);
        if ($db === null) {
            return array();
        }
        $out = array();
        foreach ($db->query('SELECT dia, sha256 FROM procesados ORDER BY dia') as $r) {
            $out[$r['dia']] = $r['sha256'];
        }
        return $out;
    }

    /* =====================================================================
     *  Portable export/import of daily aggregates (JSON lines, gzipped)
     * ===================================================================== */

    /** Append a day aggregate to an open gz handle (gzopen(..., 'ab'/'wb')). */
    public static function exportDay($gz, array $agg)
    {
        gzwrite($gz, json_encode($agg, JSON_UNESCAPED_SLASHES) . "\n");
    }

    /**
     * Import an export file into the yearly databases.
     * @return array{dias:int, omitidos:int}
     */
    public function importFile($file, $force = false)
    {
        $h = gzopen($file, 'rb');
        if ($h === false) {
            throw new \RuntimeException("Cannot open $file");
        }
        $n = 0;
        $skip = 0;
        while (($line = gzgets($h)) !== false) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $agg = json_decode($line, true);
            if (!is_array($agg) || !isset($agg['dia'])) {
                throw new \RuntimeException("Invalid line in $file");
            }
            $year = (int)substr($agg['dia'], 0, 4);
            if (!$force && is_file($this->dbFile($year)) && $this->isClosed($year)) {
                $skip++;
                continue;
            }
            $this->storeDay($agg, 'importado:' . basename($file), $force);
            $n++;
        }
        gzclose($h);
        return array('dias' => $n, 'omitidos' => $skip);
    }

    /* =====================================================================
     *  Queries
     * ===================================================================== */

    /**
     * Run $sql (must use :desde/:hasta on column 'dia') on every year
     * database overlapping [$from, $to] and return all rows.
     */
    public function queryRange($sql, $from, $to)
    {
        $rows = array();
        for ($y = (int)substr($from, 0, 4); $y <= (int)substr($to, 0, 4); $y++) {
            $db = $this->db($y);
            if ($db === null) {
                continue;
            }
            $st = $db->prepare($sql);
            $st->execute(array(':desde' => $from, ':hasta' => $to));
            foreach ($st->fetchAll(\PDO::FETCH_ASSOC) as $r) {
                $rows[] = $r;
            }
        }
        return $rows;
    }

    /** Legacy counters of one day (or null if not processed). */
    public function compatDay($day)
    {
        $db = $this->db((int)substr($day, 0, 4));
        if ($db === null) {
            return null;
        }
        $st = $db->prepare('SELECT total_requests, total_responses, saml_requests, eidas_requests, stork_requests
                            FROM dia_compat WHERE dia = ?');
        $st->execute(array($day));
        $r = $st->fetch(\PDO::FETCH_ASSOC);
        return $r === false ? null : array_map('intval', $r);
    }

    /* =====================================================================
     *  Year close / retention
     * ===================================================================== */

    /**
     * Close a year: integrity check, VACUUM, mark closed and leave a
     * compressed copy + sha256 in $exportDir for archiving.
     * @return string path of the compressed copy
     */
    public function closeYear($year, $exportDir)
    {
        $db = $this->db($year);
        if ($db === null) {
            throw new \RuntimeException("No database for $year");
        }
        $ok = $db->query('PRAGMA integrity_check')->fetchColumn();
        if ($ok !== 'ok') {
            throw new \RuntimeException("Integrity check of $year failed: $ok");
        }
        $this->setMeta($year, 'cerrado', gmdate('c'));
        $db->exec('VACUUM');
        if (!is_dir($exportDir)) {
            mkdir($exportDir, 0750, true);
        }
        $dst = rtrim($exportDir, '/') . '/stats-' . (int)$year . '.sqlite.gz';
        $in = fopen($this->dbFile($year), 'rb');
        $out = gzopen($dst . '.tmp', 'wb9');
        while (!feof($in)) {
            gzwrite($out, fread($in, 1048576));
        }
        fclose($in);
        gzclose($out);
        rename($dst . '.tmp', $dst);
        file_put_contents($dst . '.sha256', hash_file('sha256', $dst) . '  ' . basename($dst) . "\n");
        return $dst;
    }

}
