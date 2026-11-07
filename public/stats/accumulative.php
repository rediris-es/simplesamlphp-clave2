<?php

// Here we return metrics which we keep a history of
// it accepts parameters to return the accumulated value of period
//
// Reads the per-year statistics databases (src/Stats/StatsDb.php, filled by
// bin/clave-stats.php). Days not processed yet (e.g. today) are read from
// the raw statistics file, so 'current' still returns the partial month.
// Paths come from the SimpleSAMLphp configuration (see StatsDb::sspPaths()).

use SimpleSAML\Module\clave\Stats\StatsDb;

// Output is buffered until the end of the request: SimpleSAMLphp may still
// need to send headers (session cookie for deferred log messages) after this
// script has written the CSV.
ob_start();

#Param: start_month (year-month | null )
#     i.e. 2020-12, don't send to get just one month before end_month
#Param: end_month (year-month | current | last )
#     i.e. 2021-03, don't send to get last completed
#     month (same as sending 'last'). Send 'current'
#     to get a partial result for ongoing month

$start_month = null;
$end_month = 'last';

if(isset($_REQUEST['start_month']))
    $start_month = $_REQUEST['start_month'];
if(isset($_REQUEST['end_month']))
    $end_month = $_REQUEST['end_month'];



if($end_month == 'last'){
    $end_month = date('Y-m', strtotime('last month'));
}
if($end_month == 'current'){
    $end_month = date('Y-m', strtotime('this month'));
}

if($start_month == null){
    $start_month = $end_month;
}
if($start_month != null){
    //Check syntax of parameter is a valid date
    if (!strtotime($start_month)){
        header($_SERVER["SERVER_PROTOCOL"]." 400 start_month bad syntax");
        die(0);
    }
}

//Check syntax of parameter is a valid date
if (!strtotime($end_month)){
    header($_SERVER["SERVER_PROTOCOL"]." 400 end_month bad syntax");
    die(0);
}

//Get the starting year and month separately to loop

$year_ini = date_parse($start_month)['year'];
$month_ini = date_parse($start_month)['month'];

$year_end = date_parse($end_month)['year'];
$month_end = date_parse($end_month)['month'];


list($dbdir, $rawdir) = StatsDb::sspPaths();
$stats = new StatsDb($dbdir);

//Metrics variables
$m = array('total_requests' => 0, 'total_responses' => 0,
           'saml_requests' => 0, 'eidas_requests' => 0, 'stork_requests' => 0);

for($year=$year_ini; $year<=$year_end; $year++){

    //First year's starting month might not be 01; last year's ending month might not be 12
    $firstmonth = ($year == $year_ini) ? $month_ini : 1;
    $lastmonth  = ($year == $year_end) ? $month_end : 12;

    for($month=$firstmonth; $month<=$lastmonth; $month++){

        $last_day = cal_days_in_month(CAL_GREGORIAN, $month, $year);

        for($day=1; $day<=$last_day; $day++) {

            $date_string = sprintf('%04d-%02d-%02d', $year, $month, $day);

            // Processed day: from the database. Otherwise: the raw file, if any.
            $c = $stats->compatDay($date_string);
            if ($c === null && $rawdir !== null) {
                $raw = StatsDb::rawFile($rawdir, $date_string);
                if ($raw !== null) {
                    $agg = StatsDb::aggregateFile($raw, $date_string);
                    $c = $agg['compat'];
                }
            }

            // Day 1 of a month must have data (no full month records otherwise)
            if ($c === null && $day == 1) {
                header($_SERVER["SERVER_PROTOCOL"] . " 400 no data for " . sprintf('%04d-%02d', $year, $month));
                die(0);
            }
            if ($c === null)
                continue;

            foreach ($m as $k => $v)
                $m[$k] += (int)$c[$k];
        }
    }
}

// Now print the metrics:

header("Content-type: text/csv");
header("Content-disposition: attachment; filename = stats_clave_usage_{$year_ini}-{$month_ini}_{$year_end}-{$month_end}.csv");


// Requests
echo "total_requests, {$m['total_requests']}\n";

// Completed authentications
echo "total_responses, {$m['total_responses']}\n";

// Requests in standard saml
echo "saml_requests, {$m['saml_requests']}\n";

// Requests in eidas saml
echo "eidas_requests, {$m['eidas_requests']}\n";

// Requests in stork saml
echo "stork_requests, {$m['stork_requests']}\n";
