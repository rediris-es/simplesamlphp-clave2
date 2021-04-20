<?php

// Here we return metrics which we keep a history of
// it accepts parameters to return the accumulated value of period

const STATS_DIR = "/var/log/clave/stats2";

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


//Metrics variables

// Requests
$total_requests = 0;
// Completed authentications
$total_responses = 0;
// Requests in standard saml
$saml_requests = 0;
// Requests in eidas saml
$eidas_requests = 0;
// Requests in stork saml
$stork_requests = 0;

for($year=$year_ini; $year<=$year_end; $year++){

    $firstmonth = 1;
    $lastmonth = 12;
    //First year's starting month might not be 01
    if($year == $year_ini)
        $firstmonth = $month_ini;
    //Last year's ending month might not be 12
    if($year == $year_ini)
        $lastmonth = $month_end;

    for($month=$firstmonth; $month<=$lastmonth; $month++){

        $first_day = 1;
        $last_day =  cal_days_in_month(CAL_GREGORIAN, $month, $year);

        for($day=$first_day; $day<=$last_day; $day++) {

            //Normalise date string to seek the log file
            $timestamp = strtotime("$year-$month-$day");
            if ($timestamp === false) {
                header($_SERVER["SERVER_PROTOCOL"] . " 400 bad date syntax");
                die(0);
            }
            $date_string = date('Y-m-d', $timestamp);

            //File path
            $filepath = STATS_DIR."/".$date_string.".log";

            // If day 1 of month, check if file exists and if not fail (no full month records)
            if ($day == $first_day) {
                if(!file_exists($filepath)){
                    header($_SERVER["SERVER_PROTOCOL"] . " 400 end_month bad syntax");
                    die(0);
                }
            }

            // For each day, read the file to array of lines
            $daylog = file($filepath,FILE_IGNORE_NEW_LINES);

            //Process each entry and accumulate on the indicators
            foreach ($daylog as $entrystr){
                $entry = json_decode(preg_replace('!^.*?({)!',"\$1",$entrystr));


                // It is a request
                if($entry->op == "saml:idp:AuthnRequest" ||
                    $entry->op == "clave:idp:AuthnRequest"){
                    $total_requests++;
                    // It is in standard saml
                    if($entry->protocol == "saml2")
                        $saml_requests++;
                    // Requests in eidas saml
                    else if($entry->protocol == "saml2-eidas")
                        $eidas_requests++;
                    // Requests in stork saml
                    else if($entry->protocol == "saml2-stork")
                        $stork_requests++;

                }
                // It is a completed authentication
                else if($entry->op == "clave:sp:Response")
                    $total_responses++;
            }
        }
    }
}

// Now print the metrics:

header("Content-type: text/csv");
header("Content-disposition: attachment; filename = stats_clave_usage_$year_ini-${month_ini}_$year_end-$month_end.csv");


// Requests
echo "total_requests, $total_requests\n";

// Completed authentications
echo "total_responses, $total_responses\n";

// Requests in standard saml
echo "saml_requests, $saml_requests\n";

// Requests in eidas saml
echo "eidas_requests, $eidas_requests\n";

// Requests in stork saml
echo "stork_requests, $stork_requests\n";