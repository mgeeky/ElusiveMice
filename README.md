# ElusiveMice - custom Cobalt Strike User-Defined Reflective Loader 

This is a fork of [Cobalt Strike's User-Defined Reflective Loader](https://www.cobaltstrike.com/help-user-defined-reflective-loader) which in turn is a fork of [Stephen Fewer's ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) implementation, but with a _slight_ plot twist - it adds a few well-known AV/EDR evasion hooks/patches!

Whenever we issue `execute-assembly` or perform any other Cobalt-Strike native action that injects capability into a sacrificial process, the Cobalt Strike will utilize its Reflective Loader to inject DLL into a remote process, instantiate it and execute our action. The thing is though, that sometimes we might come across EDR triggering alerts not during the mere process-injection but afterwards, as soon as the injected .NET assembly or our keylogger/screenshot capability invokes monitored API, or issues unsafe script.

We can attempt to combat these detections by pre-pending our injected capabilities with some preliminary hot-patches.

At the end of the day, we Red Teamers are getting paid for _raising the bar_, aren't we? :)


## Features

- Avoids use of RWX pages wherever possible, sticks to RX+RW instead. Also, sets per-section permissions
- Wipes own PE Headers and most of the ReflectiveLoader's function code by zeroing them out.
- AMSI Bypass through `amsi!AmsiScanBuffer` one-byte memory patch incrementing `'AMSI'` constant in assembly
- ETW Bypass through `ntdll!EtwEventWrite` memory patch (_return 0_ technique)
- _(Temporarily not used)_ ~WLDP Bypass through `wdlp!WldpQueryDynamicCodeTrust` memory patch~
- utilizes changed API/module name dynamic resolution hashes to avoid simple signature detections


## Usage

1. Load `rdll_loader.cna` script into Cobalt Strike
2. Generate your beacon via `Attacks -> Packages -> Windows Executable (S)` or any other sort of Beacon's shellcode.
3. (Optionally) observe output in `View -> Script Console`

The CNA script may have `$debug` mode enabled by flipping the variable:

```
# Enable Debug of PE content
# The generated PE content will be displayed in the script console if debug is true

#$debug = "true";
$debug = "false";
```

Which will dump PE headers of newly generated Reflective DLL containing Beacon's codebase.

## TODO

Most of these features are going to be possible to be added when Cobalt Strike increase it's bytes limit for UDRLs (that's currently 5KB)...

- Refactoring dumb memory patches into more subtle hooked implementations of routine wrappers for `AmsiScanBuffer` or `EtwEventWrite`
- Implement ETW unregistration instead of brutal memory patching.
- Introduce typical anti-emulation/anti-sandboxing guardrails - delaying execution, validating safe environments (_am I, the ReflectiveLoader, running inside of an emulator?_)
- Add [Raphael's `unhook-bof`](https://github.com/rsmudge/unhook-bof) implementation to _Reflective Loader_
- Add memory scanning routine eliminating dangling allocations with previous Cobalt Strike stagers
- Hook Sleep to introduce Heap encryption

## Known Issues

- **x86 Reflective Loader does not work at the moment!** (that's why it is not available in this repository)


## Other work

So far there aren't many publicly available implementations of _User-Defined Reflective Loaders_, but the ones of a great quality that I'm aware of include:

- [boku7's CobaltStrikeReflectiveLoader](https://github.com/boku7/CobaltStrikeReflectiveLoader) - reimplemting the idea in pure inline Assembly, thwarting naive static signatures (and oh, it too comes with AMSI and ETW patches!)
- [SecIdiot TitanLdr](https://github.com/SecIdiot/TitanLdr) - Reflective Loader written in C and assembly for Cobalt Strike. Redirects DNS Beacon over DoH




---

### ☕ Show Support ☕

This and other projects are outcome of sleepless nights and **plenty of hard work**. If you like what I do and appreciate that I always give back to the community,
[Consider buying me a coffee](https://github.com/sponsors/mgeeky) _(or better a beer)_ just to say thank you! 💪 

---

## Author

```   
   Mariusz B. / mgeeky, 21
   <mb [at] binary-offensive.com>
   (https://github.com/mgeeky)
```
