# TickTock

This repository demonstrates a PoC memory scanner for enumerating timer-queue timers as used in Ekko Sleep Obfuscation: https://github.com/Cracked5pider/Ekko. For a full technical walkthrough please see the accompanying blog post here: https://labs.withsecure.com/publications/hunting-for-timer-queue-timers.html.

The screenshot below demonstrates the results of scanning for timer-queue timers while Ekko is running:

<img width="643" alt="HuntingForTimers_TickTock" src="https://user-images.githubusercontent.com/108275364/194870994-c4ab4736-0b65-46fb-9196-7adc8dfc61db.PNG">

NB As a word of caution this PoC was tested on Windows 10 1607 and Windows 10 21h2. However, as it relies on undocumented functionality it may break due to future Windows releases.

Additionally, this tool requires symbols to be correctly configured and hence you will need to install the Debugging Tools for Windows (WinDbg) as a pre-requisite.

# Related Work
https://github.com/joe-desimone/patriot
