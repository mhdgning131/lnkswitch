# LNK target spoofing generator
---

> Originally inspired by [Wietze](https://github.com/wietze) on his [Link-It-Up](https://github.com/wietze/lnk-it-up) project !

This script generate Windows Short with a fake displayed target, but launch a different file on click !

1. The Specified displayed decoy and the real executed target must exist on the system
2. The LNK icon depend on the specified decoy file type

---

# Usage

```powershell
python lnkswitch_generator.py --target "C:\Windows\System32\calc.exe" \
   --display "C:\Users\Mohamed\Documents\BTS-Cyber-Securite.pdf" \
   --read-only \
   --output bts.lnk
```

- `--target` is the real file that is launched on click
- `--display` is the displayed file path in properties box
- `--read-only` prevent explorer.exe to recreate the lnk on icon change, destroying the trick (showing real target in properties box)
- `--output` really man ??

---

Actually Icon auto changing system doesn't work (tested on 11 25H2) Explorer fail to manage icon indexes in Shell32 or imageres. No idea how to come through
If you can contribute that would be a lot ❤️