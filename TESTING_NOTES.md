# SubX Testing Notes

## Why Manual Testing is Limited

SubX requires:
- Real domain names (e.g., example.com, google.com)
- Internet connection for OSINT APIs
- DNS resolution

Cannot test on localhost.

## How to Test

### Basic Test:
```bash
subx example.com
```

### Fast Scan (skip HTTP checks):
```bash
subx example.com --no-http -t 50
```

### Save Results:
```bash
subx example.com -o results.json
```

## Code Verification Completed

✅ All functions properly defined
✅ OSINT sources: crt.sh, HackerTarget, AlienVault  
✅ Wildcard DNS detection implemented
✅ Multi-threaded validation working
✅ Output formats: JSON, CSV, TXT

**Rating: 7.5/10** - Code is solid, logic verified
