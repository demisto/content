/* US CERT Rule */

rule Dropper_DeploysMalwareViaSideLoading {
meta:
        description = "Detect a dropper used to deploy an implant via side loading. This dropper has specifically been observed deploying REDLEAVES & PlugX"
        author = "USG"
        true_positive = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481: drops REDLEAVES. 6392e0701a77ea25354b1f40f5b867a35c0142abde785a66b83c9c8d2c14c0c3: drops plugx. "
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"

strings:
        $UniqueString = {2e 6c 6e 6b [0-14] 61 76 70 75 69 2e 65 78 65} // ".lnk" near "avpui.exe"
        $PsuedoRandomStringGenerator = {b9 1a [0-6] f7 f9 46 80 c2 41 88 54 35 8b 83 fe 64} // Unique function that generates a 100 character pseudo random string.

condition:
        any of them
}