#!/usr/bin/env python3
"""Stand-in for the historical AutoRun 'open=' target.

In the classic USB-drop chain an `autorun.inf` pointed `open=` at a launcher
like this, which then ran the payload on insertion. On modern Windows the
AutoRun `open=` directive is ignored for USB mass storage, so this launcher
only runs when a person double-clicks it — the human click that awareness
training is meant to prevent.

Kept benign on purpose: it just calls the recon beacon.
"""

import usb_payload_sim

if __name__ == "__main__":
    usb_payload_sim.usb_payload_sim("recon_log.txt")
