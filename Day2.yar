rule TTP_Extract_URLs_serving_PHP {
  meta:
    Description = "This YARA rule extracts URLs serving PHP web pages using REGEX in YARA"
    Author = "RustyNoob619"
    Instruction = "Run YARA with the strings output -s option to fetch all PHP URLs"
  strings:
    $httpsURLs = /https:.{2,100}php/ //Hardcoded PHP URLs in the samples
    $httpURLs = /http:.{2,100}php/ //Hardcoded PHP URLs in the samples
  condition:
    any of them
          
  }
