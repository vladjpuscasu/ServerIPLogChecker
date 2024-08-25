# ServerIPLogChecker
The following module takes a server log file and parses IP's with more than 100 hits and runs them through the AbuseIPDB API to check their locations and sorts them by highest abuseConfidenceScore. You will need abuseIPDB api key *free* as well as have Python and Requests installed - pip install requests
