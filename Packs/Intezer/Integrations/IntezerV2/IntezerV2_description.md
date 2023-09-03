Intezer is a cloud-based malware detection and analysis provides a fast, in-depth understanding of any file by mapping its code DNA.
See [https://analyze.intezer.com](https://analyze.intezer.com/account-details) for creating an API key and more details.

In order to use 'Intezer-scan host' playbook, you should add the latest version of intezer scanner tool (you can find it under https://analyze.intezer.com).
After downloading the scanner, add it to your Cortex XSOAR agent tool library(Settings->Integrations->agent tools).
You should upload a zip file named 'Scanner' with the 'Scanner.exe' file inside it. (Files names are case sensitive)

Notice: Submitting indicators using the ***intezer-analyze-url*** command of this integration might make the indicator data publicly available.  See the vendor’s documentation for more details.