# ServerIPLogChecker
The following module takes a server log file and parses IP's with more than 100 hits, runs them through the AbuseIPDB API to check their locations and sorts them by highest abuseConfidenceScore. A module that should help find malicious IP's. You will need an abuseIPDB API key *free at http://abuseipdb.com/* as well as have Python and Requests installed - pip install requests
