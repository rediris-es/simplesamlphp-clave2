<?php
/**
 * clave-stats.php — usage statistics of the Clave bridge (see src/Stats/StatsDb.php)
 *
 * Usage: php clave-stats.php COMMAND [options]
 *
 *  diario     --raw DIR --db DIR [--retener-raw 35] [--ssp DIR] [--export DIR] [--silencioso]
 *             Daily job: aggregate every complete day not yet processed, gzip
 *             processed raw files, delete processed raw files older than
 *             --retener-raw days (only days already in the database), store
 *             today's SP catalogue (with --ssp), and close + pack complete past
 *             years (compressed copy + sha256 in --export, default DB/archivo).
 *             Yearly databases are NEVER deleted: removing old years (after
 *             archiving their packed copy) is left to the administrator.
 *  procesar   --raw DIR --db DIR (--dia YYYY-MM-DD | --desde D --hasta D) [--forzar]
 *  exportar   --raw DIR [--raw DIR ...] --salida FILE.jsonl.gz [--hasta YYYY-MM-DD]
 *             Aggregate raw files WITHOUT SQLite (e.g. on an old host) into a
 *             portable file of daily aggregates. Then "importar" elsewhere.
 *  importar   --db DIR FILE.jsonl.gz [...] [--forzar]
 *  catalogo   --db DIR --ssp DIR [--dia YYYY-MM-DD]
 *             Snapshot of the SPs in the metadata (needs SimpleSAMLphp:
 *             --ssp = its code dir, SIMPLESAMLPHP_CONFIG_DIR = its config).
 *  informe    --db DIR [--mes YYYY-MM|last] [--csv FILE] [--titulo TEXT]
 *             Monthly report (text on stdout; SP ranking as CSV in --csv).
 *  csv        --db DIR --desde YYYY-MM[-DD] --hasta YYYY-MM[-DD] --por dia|mes|sp|metodo|hora|estado
 *  cerrar-anio --db DIR ANIO [--export DIR]   (close + pack a year by hand; the daily job does it)
 *  estado     --db DIR           (years, processed days, closed, packed copy)
 *
 * Runs with PHP >= 7.2. SQLite (pdo_sqlite) is only needed by the commands
 * that use --db.
 */

if (!class_exists('SimpleSAML\Module\clave\Stats\StatsDb')) {
    require __DIR__ . '/../src/Stats/StatsDb.php';
}
use SimpleSAML\Module\clave\Stats\StatsDb;

error_reporting(E_ALL);
date_default_timezone_set('UTC');

$GLOBALS['QUIET'] = false;
function out($s) { if (@fwrite(STDOUT, $s . "\n") === false) { exit(0); } }   // reader gone (e.g. "| head"): stop quietly
function note($s) { if (!$GLOBALS['QUIET']) { fwrite(STDERR, "[+] $s\n"); } }
function warnmsg($s) { fwrite(STDERR, "[!] $s\n"); }
function fail($s) { fwrite(STDERR, "[x] $s\n"); exit(1); }

/** Parse "--opt value" / "--flag" / positional. */
function parseArgs(array $argv)
{
    $o = array('_' => array());
    $flags = array('forzar', 'silencioso');
    for ($i = 0; $i < count($argv); $i++) {
        $a = $argv[$i];
        if (strpos($a, '--') === 0) {
            $k = substr($a, 2);
            if (in_array($k, $flags, true)) {
                $o[$k] = true;
            } else {
                if (!isset($argv[$i + 1])) {
                    fail("Falta el valor de --$k");
                }
                $v = $argv[++$i];
                if (isset($o[$k])) {
                    $o[$k] = array_merge((array)$o[$k], array($v));
                } else {
                    $o[$k] = $v;
                }
            }
        } else {
            $o['_'][] = $a;
        }
    }
    return $o;
}

function need(array $o, $k)
{
    if (!isset($o[$k]) || $o[$k] === '') {
        fail("Falta --$k");
    }
    return $o[$k];
}

function today() { return gmdate('Y-m-d'); }

function monthRange($ym)
{
    if ($ym === 'last' || $ym === null) {
        $ym = gmdate('Y-m', strtotime(gmdate('Y-m-01') . ' -1 month'));
    }
    if (!preg_match('/^\d{4}-\d{2}$/', $ym)) {
        fail("Mes no válido: $ym (YYYY-MM)");
    }
    return array($ym, "$ym-01", gmdate('Y-m-t', strtotime("$ym-01")));
}

function prevMonth($ym, $n = 1)
{
    return gmdate('Y-m', strtotime("$ym-01 -$n month"));
}

/** Institution of an entityID: registrable-ish domain (same rule as the legacy page). */
function institutionOf($entityID)
{
    $domain = preg_replace('!(http(s)?://)?([^/:]+)(:[0-9]+)?(/)?.*$!', '$3', $entityID);
    if ($domain === null || $domain === '') {
        return '';
    }
    return (string)preg_replace('!^.*?([-a-zA-Z0-9]+\.[a-zA-Z]+)$!', '$1', $domain);
}

/** Load SimpleSAMLphp (for the catalogue). */
function loadSsp($sspDir)
{
    $a = rtrim($sspDir, '/') . '/vendor/autoload.php';
    if (!is_file($a)) {
        fail("No es un directorio de SimpleSAMLphp: $sspDir");
    }
    require_once $a;
}

/** SPs in the metadata: list of [entityID, name, institution]. */
function catalogRows()
{
    $h = \SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();
    $rows = array();
    foreach ($h->getList('saml20-sp-remote') as $id => $m) {
        $name = '';
        foreach (array('OrganizationDisplayName', 'OrganizationName', 'name') as $k) {
            if (!empty($m[$k])) {
                $v = $m[$k];
                $name = is_array($v) ? (isset($v['es']) ? $v['es'] : (isset($v['en']) ? $v['en'] : reset($v))) : $v;
                break;
            }
        }
        $rows[] = array($id, (string)$name, institutionOf($id));
    }
    return $rows;
}

function pct($a, $b) { return $b > 0 ? sprintf('%.1f%%', 100.0 * $a / $b) : '-'; }
function delta($now, $before) { return $before > 0 ? sprintf('%+.1f%%', 100.0 * ($now - $before) / $before) : 'n/d'; }

/* ------------------------------------------------------------------------- */

$args = $argv;
array_shift($args);
$cmd = array_shift($args);
$o = parseArgs($args);
$GLOBALS['QUIET'] = !empty($o['silencioso']);   // only warnings/errors (for cron)

switch ($cmd) {

case 'procesar':
case 'diario':
    $raw = need($o, 'raw');
    $sdb = new StatsDb(need($o, 'db'));
    $days = StatsDb::rawDays($raw);
    $today = today();
    if ($cmd === 'procesar') {
        $from = isset($o['dia']) ? $o['dia'] : need($o, 'desde');
        $to = isset($o['dia']) ? $o['dia'] : need($o, 'hasta');
        $todo = array();
        foreach ($days as $d => $f) {
            if ($d >= $from && $d <= $to) {
                $todo[$d] = $f;
            }
        }
        if (!$todo) {
            fail("No hay ficheros en $raw entre $from y $to");
        }
    } else {
        $todo = array();
        foreach ($days as $d => $f) {
            if ($d < $today && !$sdb->isProcessed($d)) {
                $todo[$d] = $f;     // complete days (UTC) still pending
            }
        }
    }
    $n = 0;
    foreach ($todo as $d => $f) {
        $agg = StatsDb::aggregateFile($f, $d);
        $sdb->storeDay($agg, $f, !empty($o['forzar']));
        note(sprintf('%s: %d eventos (%d inválidos) -> %d SP', $d, $agg['lineas'], $agg['invalidas'], count($agg['sp'])));
        $n++;
    }
    if ($cmd === 'procesar') {
        note("$n días procesados");
        break;
    }
    // --- daily housekeeping on raw files: only processed, complete days ---
    $keep = isset($o['retener-raw']) ? (int)$o['retener-raw'] : 35;
    $limit = gmdate('Y-m-d', strtotime("$today -$keep day"));
    $gz = 0;
    $del = 0;
    foreach (StatsDb::rawDays($raw) as $d => $f) {
        if ($d >= $today || !$sdb->isProcessed($d)) {
            continue;
        }
        if ($d < $limit) {
            foreach (array("$raw/$d.log", "$raw/$d.log.gz") as $x) {
                if (is_file($x) && unlink($x)) {
                    $del++;
                }
            }
        } elseif (substr($f, -3) !== '.gz') {
            $in = fopen($f, 'rb');
            $outh = gzopen("$f.gz.tmp", 'wb9');
            while (!feof($in)) {
                gzwrite($outh, fread($in, 1048576));
            }
            fclose($in);
            gzclose($outh);
            @chown("$f.gz.tmp", fileowner($f));
            @chgrp("$f.gz.tmp", filegroup($f));
            chmod("$f.gz.tmp", fileperms($f) & 0777);
            rename("$f.gz.tmp", "$f.gz");
            unlink($f);
            $gz++;
        }
    }
    note("$n días procesados; $gz ficheros comprimidos; $del ficheros de más de $keep días eliminados");
    // --- catalogue snapshot ---
    if (isset($o['ssp'])) {
        loadSsp($o['ssp']);
        $rows = catalogRows();
        $sdb->storeCatalog($today, $rows);
        note('catálogo: ' . count($rows) . " SP registrados ($today)");
    }
    // --- past years (previous one, or older ones imported from history): close once complete ---
    foreach ($sdb->years() as $prev) {
        if ($prev >= (int)gmdate('Y') || $sdb->isClosed($prev)) {
            continue;
        }
        $pending = false;
        foreach (StatsDb::rawDays($raw) as $d => $f) {
            if ((int)substr($d, 0, 4) === $prev && !$sdb->isProcessed($d)) {
                $pending = true;
            }
        }
        if (!$pending) {
            $exp = isset($o['export']) ? $o['export'] : $sdb->getDir() . '/archivo';
            $copy = $sdb->closeYear($prev, $exp);
            note("año $prev cerrado y empaquetado: $copy (+ .sha256). La base de datos se conserva; borrarla es decisión del administrador.");
        }
    }
    // Yearly databases are never deleted here: closed years stay, with their
    // packed copy in archivo/, until someone removes them by hand.
    break;

case 'exportar':
    $raws = (array)need($o, 'raw');
    $outf = need($o, 'salida');
    $until = isset($o['hasta']) ? $o['hasta'] : gmdate('Y-m-d', strtotime(today() . ' -1 day'));
    $all = array();
    foreach ($raws as $r) {
        foreach (StatsDb::rawDays($r) as $d => $f) {
            if ($d > $until) {
                continue;
            }
            if (isset($all[$d])) {
                warnmsg("$d está en varios directorios: se usa $all[$d], se ignora $f");
                continue;
            }
            $all[$d] = $f;
        }
    }
    ksort($all);
    if (!$all) {
        fail('No hay ficheros de estadísticas que exportar');
    }
    $gz = gzopen($outf . '.tmp', 'wb9');
    $ev = 0;
    foreach ($all as $d => $f) {
        $agg = StatsDb::aggregateFile($f, $d);
        StatsDb::exportDay($gz, $agg);
        $ev += $agg['lineas'];
    }
    gzclose($gz);
    rename($outf . '.tmp', $outf);
    file_put_contents($outf . '.sha256', hash_file('sha256', $outf) . '  ' . basename($outf) . "\n");
    note(sprintf('%d días (%s .. %s), %d eventos -> %s (%d KB)', count($all), key($all), $d, $ev, $outf, filesize($outf) / 1024));
    break;

case 'importar':
    $sdb = new StatsDb(need($o, 'db'));
    if (!$o['_']) {
        fail('Indicar el fichero (o ficheros) .jsonl.gz');
    }
    foreach ($o['_'] as $f) {
        if (is_file($f . '.sha256')) {
            $want = strtok(file_get_contents($f . '.sha256'), ' ');
            if ($want !== hash_file('sha256', $f)) {
                fail("$f: el sha256 no coincide con $f.sha256");
            }
        }
        $r = $sdb->importFile($f, !empty($o['forzar']));
        note("$f: {$r['dias']} días importados" . ($r['omitidos'] ? ", {$r['omitidos']} omitidos (años cerrados; --forzar)" : ''));
    }
    foreach ($sdb->years() as $y) {
        note("  stats-$y.sqlite: " . count($sdb->processedDays($y)) . ' días');
    }
    break;

case 'catalogo':
    $sdb = new StatsDb(need($o, 'db'));
    loadSsp(need($o, 'ssp'));
    $day = isset($o['dia']) ? $o['dia'] : today();
    $rows = catalogRows();
    $sdb->storeCatalog($day, $rows);
    note(count($rows) . " SP registrados guardados en el catálogo de $day");
    break;

case 'csv':
    $sdb = new StatsDb(need($o, 'db'));
    $from = need($o, 'desde');
    $to = need($o, 'hasta');
    if (strlen($from) === 7) { $from .= '-01'; }
    if (strlen($to) === 7) { $to = gmdate('Y-m-t', strtotime("$to-01")); }
    $by = need($o, 'por');
    $q = array(
        'dia'    => array('dia;intentos;exitos;cancelaciones;fallos;sesiones',
                          'SELECT dia, SUM(intentos), SUM(exitos), SUM(cancelaciones), SUM(fallos), SUM(sesiones) FROM dia_sp WHERE dia BETWEEN :desde AND :hasta GROUP BY dia'),
        'mes'    => array('mes;intentos;exitos;cancelaciones;fallos;sesiones',
                          'SELECT substr(dia,1,7), SUM(intentos), SUM(exitos), SUM(cancelaciones), SUM(fallos), SUM(sesiones) FROM dia_sp WHERE dia BETWEEN :desde AND :hasta GROUP BY substr(dia,1,7)'),
        'sp'     => array('sp;protocolo;intentos;exitos;cancelaciones;fallos;sesiones',
                          'SELECT sp, protocolo, SUM(intentos), SUM(exitos), SUM(cancelaciones), SUM(fallos), SUM(sesiones) FROM dia_sp WHERE dia BETWEEN :desde AND :hasta GROUP BY sp, protocolo'),
        'metodo' => array('metodo;exitos;errores',
                          'SELECT metodo, SUM(exitos), SUM(errores) FROM dia_metodo WHERE dia BETWEEN :desde AND :hasta GROUP BY metodo'),
        'hora'   => array('hora_utc;intentos;exitos',
                          'SELECT hora, SUM(intentos), SUM(exitos) FROM dia_hora WHERE dia BETWEEN :desde AND :hasta GROUP BY hora'),
        'estado' => array('sp;estado;n',
                          'SELECT sp, estado, SUM(n) FROM dia_estado WHERE dia BETWEEN :desde AND :hasta GROUP BY sp, estado'),
    );
    if (!isset($q[$by])) {
        fail('--por: ' . implode('|', array_keys($q)));
    }
    // Several years: aggregate per year in SQL, then merge here
    $merged = array();
    foreach ($sdb->queryRange($q[$by][1], $from, $to) as $r) {
        $r = array_values($r);
        $keyCols = ($by === 'sp' || $by === 'estado') ? 2 : 1;
        $k = implode("\t", array_slice($r, 0, $keyCols));
        if (!isset($merged[$k])) {
            $merged[$k] = $r;
        } else {
            for ($i = $keyCols; $i < count($r); $i++) {
                $merged[$k][$i] += $r[$i];
            }
        }
    }
    ksort($merged);
    out($q[$by][0]);
    foreach ($merged as $r) {
        out(implode(';', array_map(function ($v) { return strpos((string)$v, ';') !== false ? '"' . $v . '"' : $v; }, $r)));
    }
    break;

case 'informe':
    $sdb = new StatsDb(need($o, 'db'));
    list($ym, $from, $to) = monthRange(isset($o['mes']) ? $o['mes'] : 'last');
    $tot = function ($f, $t) use ($sdb) {
        $r = array('intentos' => 0, 'exitos' => 0, 'cancelaciones' => 0, 'fallos' => 0, 'sesiones' => 0);
        foreach ($sdb->queryRange('SELECT SUM(intentos) intentos, SUM(exitos) exitos, SUM(cancelaciones) cancelaciones,
                SUM(fallos) fallos, SUM(sesiones) sesiones FROM dia_sp WHERE dia BETWEEN :desde AND :hasta', $f, $t) as $x) {
            foreach ($r as $k => $v) { $r[$k] += (int)$x[$k]; }
        }
        return $r;
    };
    $daysDone = count($sdb->queryRange('SELECT dia FROM procesados WHERE dia BETWEEN :desde AND :hasta', $from, $to));
    if ($daysDone === 0) {
        fail("No hay datos procesados de $ym");
    }
    $cur = $tot($from, $to);
    list($pm, $pf, $pt) = monthRange(prevMonth($ym));
    list($ly, $lf, $lt) = monthRange(prevMonth($ym, 12));
    $prv = $tot($pf, $pt);
    $lst = $tot($lf, $lt);
    // comparisons against months with missing days are flagged
    $days = function ($f, $t) use ($sdb) { return count($sdb->queryRange('SELECT dia FROM procesados WHERE dia BETWEEN :desde AND :hasta', $f, $t)); };
    $partial = function ($f, $t) use ($days) { $n = $days($f, $t); $all = (int)gmdate('t', strtotime($f)); return ($n > 0 && $n < $all) ? " [incompleto: $n/$all días]" : ''; };
    $title = isset($o['titulo']) ? $o['titulo'] : 'Pasarela Cl@ve';
    out("$title — estadísticas de $ym");
    out(str_repeat('=', 60));
    out(sprintf('Días con datos: %d de %d', $daysDone, (int)gmdate('t', strtotime($from))));
    out('');
    out(sprintf('Intentos de autenticación:   %8d   (vs %s: %s%s, vs %s: %s%s)', $cur['intentos'],
                $pm, delta($cur['intentos'], $prv['intentos']), $partial($pf, $pt),
                $ly, delta($cur['intentos'], $lst['intentos']), $partial($lf, $lt)));
    out(sprintf('Autenticaciones con éxito:   %8d   (%s de los intentos)', $cur['exitos'], pct($cur['exitos'], $cur['intentos'])));
    out(sprintf('Canceladas / fallidas en Cl@ve: %5d', $cur['cancelaciones']));
    out(sprintf('Otros errores:               %8d', $cur['fallos']));
    out(sprintf('Sesiones distintas:          %8d', $cur['sesiones']));
    out('');

    // Catalogue: last snapshot of the month (names)
    $names = array();
    $catDay = null;
    foreach ($sdb->queryRange('SELECT MAX(dia) d FROM catalogo WHERE dia BETWEEN :desde AND :hasta', $from, $to) as $x) {
        if ($x['d'] !== null) { $catDay = $x['d']; }
    }
    $registered = array();
    if ($catDay !== null) {
        foreach ($sdb->queryRange('SELECT sp, nombre, institucion FROM catalogo WHERE dia = :desde AND dia = :hasta', $catDay, $catDay) as $x) {
            $registered[$x['sp']] = $x;
            $names[$x['sp']] = $x['nombre'];
        }
    }

    // SP ranking
    $rank = array();
    foreach ($sdb->queryRange('SELECT sp, SUM(intentos) i, SUM(exitos) e, SUM(cancelaciones) c, SUM(fallos) f
            FROM dia_sp WHERE dia BETWEEN :desde AND :hasta GROUP BY sp', $from, $to) as $x) {
        if ($x['sp'] === '') { continue; }
        $rank[$x['sp']] = array((int)$x['i'], (int)$x['e'], (int)$x['c'], (int)$x['f']);
    }
    uasort($rank, function ($a, $b) { return $b[0] - $a[0]; });
    if (isset($o['csv'])) {        // written first: the text below may be cut by a closed pipe
        $fh = fopen($o['csv'], 'w');
        fwrite($fh, "sp;nombre;intentos;exitos;cancelaciones;fallos\n");
        foreach ($rank as $sp => $r) {
            $n = isset($names[$sp]) ? str_replace(';', ',', $names[$sp]) : '';
            fwrite($fh, "$sp;$n;{$r[0]};{$r[1]};{$r[2]};{$r[3]}\n");
        }
        fclose($fh);
    }
    out('Ranking de SP (intentos, éxitos, % éxito, canceladas, errores)');
    out(str_repeat('-', 60));
    $i = 0;
    foreach ($rank as $sp => $r) {
        $i++;
        $label = isset($names[$sp]) && $names[$sp] !== '' ? $names[$sp] . ' — ' . $sp : $sp;
        out(sprintf('%3d. %7d %7d %6s %6d %5d  %s%s', $i, $r[0], $r[1], pct($r[1], $r[0]), $r[2], $r[3], $label,
                    ($r[0] >= 20 && $r[1] < 0.5 * $r[0]) ? '   <-- éxito bajo' : ''));
    }
    out('');

    // Cl@ve methods
    $met = array();
    foreach ($sdb->queryRange('SELECT metodo, SUM(exitos) e, SUM(errores) r, SUM(t_n * t_p50) tw, SUM(t_n) tn, MAX(t_p95) p95
            FROM dia_metodo WHERE dia BETWEEN :desde AND :hasta GROUP BY metodo', $from, $to) as $x) {
        $met[$x['metodo']] = $x;
    }
    uasort($met, function ($a, $b) { return $b['e'] - $a['e']; });
    out('Respuestas de Cl@ve por método/IdP (éxitos, errores, tiempo en Cl@ve: mediana aprox. / p95 máx. del mes, s)');
    out(str_repeat('-', 60));
    foreach ($met as $m => $x) {
        out(sprintf('  %7d %6d  %6s / %-6s %s', $x['e'], $x['r'], $x['tn'] > 0 ? round($x['tw'] / $x['tn'], 1) : '-',
                    $x['p95'] !== null ? round($x['p95'], 1) : '-', $m === '' ? '(sin emisor)' : $m));
    }
    out('');

    // Errors
    $err = $sdb->queryRange('SELECT estado, SUM(n) n FROM dia_estado WHERE dia BETWEEN :desde AND :hasta GROUP BY estado', $from, $to);
    if ($err) {
        $e2 = array();
        foreach ($err as $x) { $e2[$x['estado']] = (isset($e2[$x['estado']]) ? $e2[$x['estado']] : 0) + (int)$x['n']; }
        arsort($e2);
        out('Estados de error devueltos a los SP');
        out(str_repeat('-', 60));
        foreach ($e2 as $s => $n) { out(sprintf('  %7d  %s', $n, $s)); }
        out('');
    }

    // Catalogue summary
    if ($registered) {
        $inst = array();
        foreach ($registered as $x) { if ($x['institucion'] !== '') { $inst[$x['institucion']] = true; } }
        $prevReg = array();
        foreach ($sdb->queryRange('SELECT sp FROM catalogo WHERE dia = (SELECT MAX(dia) FROM catalogo WHERE dia BETWEEN :desde AND :hasta)', $pf, $pt) as $x) {
            $prevReg[$x['sp']] = true;
        }
        $new = $prevReg ? array_diff(array_keys($registered), array_keys($prevReg)) : array();
        $unused = array_diff(array_keys($registered), array_keys($rank));
        $unreg = array_diff(array_keys($rank), array_keys($registered));
        out("Catálogo de SP ($catDay)");
        out(str_repeat('-', 60));
        out(sprintf('SP registrados: %d   Instituciones: %d   Nuevos este mes: %s   Sin uso este mes: %d',
                    count($registered), count($inst), $prevReg ? count($new) : 'n/d', count($unused)));
        foreach ($new as $sp) { out("  nuevo: $sp"); }
        foreach ($unreg as $sp) { out("  con peticiones pero NO registrado: $sp"); }
        out('');
    }

    // By day and last 13 months
    out('Por día (intentos / éxitos)');
    out(str_repeat('-', 60));
    foreach ($sdb->queryRange('SELECT dia, SUM(intentos) i, SUM(exitos) e FROM dia_sp WHERE dia BETWEEN :desde AND :hasta GROUP BY dia ORDER BY dia', $from, $to) as $x) {
        out(sprintf('  %s %7d %7d', $x['dia'], $x['i'], $x['e']));
    }
    out('');
    out('Últimos 13 meses (intentos / éxitos / % éxito)');
    out(str_repeat('-', 60));
    for ($k = 12; $k >= 0; $k--) {
        list($m, $f, $t) = monthRange(prevMonth($ym, $k));
        $x = $tot($f, $t);
        if ($x['intentos'] > 0) {
            out(sprintf('  %s %8d %8d %7s%s', $m, $x['intentos'], $x['exitos'], pct($x['exitos'], $x['intentos']), $partial($f, $t)));
        }
    }
    break;

case 'cerrar-anio':
    $sdb = new StatsDb(need($o, 'db'));
    $y = isset($o['_'][0]) ? (int)$o['_'][0] : fail('Indicar el año');
    $exp = isset($o['export']) ? $o['export'] : $sdb->getDir() . '/archivo';
    note('copia para archivar: ' . $sdb->closeYear($y, $exp));
    break;

case 'estado':
    $sdb = new StatsDb(need($o, 'db'));
    out('año  días  primer día  último día  cerrado                    copia empaquetada');
    foreach ($sdb->years() as $y) {
        $d = array_keys($sdb->processedDays($y));
        $copy = $sdb->getDir() . "/archivo/stats-$y.sqlite.gz";
        out(sprintf('%d %5d  %-10s  %-10s  %-26s %s', $y, count($d), $d ? $d[0] : '-', $d ? end($d) : '-',
                    $sdb->meta($y, 'cerrado') ?: '-', is_file($copy) ? $copy : '-'));
    }
    break;

default:
    fwrite(STDERR, "Uso: php clave-stats.php diario|procesar|exportar|importar|catalogo|informe|csv|cerrar-anio|estado [opciones]\n"
                 . "(ver la cabecera de este fichero)\n");
    exit($cmd === null || $cmd === 'help' || $cmd === '-h' ? 0 : 1);
}
