# XSSF plugin loading instructions #
  1. Start Metasploit Framework (MSF Console for example).
  1. Load XSSF plugin using the command '`load xssf`'.
    * XSSF server port can be modified using the command '`load xssf Port=80`'.
    * XSSF server URI can be changed using the command '`load xssf Uri=/`'.
    * Remote access to XSSF GUI and Tunnel can be activated using the command '`load xssf Public=true`'.
    * XSSF mode for information messages can be changed using the command '`load xssf Mode=???`'. Information messages are displayed during attacks or during tunnel transferts. Accepted modes are:
      * Quiet: Does not display anything.
      * Normal: Displays attacks and tunnel status messages only (default mode).
      * Verbose: Displays all 'Normal' mode messages plus received results from victims.
      * Debug: Displays all 'Verbose' mode messages plus XSSF exceptions error messages if exceptions are trigered (should not :-) ).

For example, to launch XSSF on port 80, on /xssf/ uri, with attacker's interfaces (GUI, Tunnel) available from remote and with all messages displayed from attacks, just launch XSSF with the command '`load xssf Port=80 Uri=/xssf/ Public=true Mode=Verbose`'.

**Note:** Launching XSSF victims' server on port 'x' will launch attacker' server on port 'x + 1'. Attacker' server is useful to access web GUI (logs, stats, etc.) and to access XSSF Tunnel.