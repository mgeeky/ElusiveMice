# ElusiveMice - custom Cobalt Strike User-Defined Reflective Loader 

This is a fork of [Cobalt Strike's User-Defined Reflective Loader](https://www.cobaltstrike.com/help-user-defined-reflective-loader) which in turn is a fork of [Stephen Fewer's ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) implementation, but with a _slight_ plot twist - it adds a few lightweight evasions.

## Features

- utilizes changed API/module name dynamic resolution hashes to avoid simple signature detections
- reflective loader now properly restores section memory protections and avoids using one big `RWX` allocation
- `elusiveMice` tries to wipe itself from the memory, leaving close to no remnants of UDRL code when memory scan sweep comes in


## Usage

1. Modify you `arsenal_kit.config` accordingly:

```
include_artifact_kit="true"
include_udrl_kit="false"
include_sleepmask_kit="true"
include_process_inject_kit="true"
include_resource_kit="true"
include_mimikatz_kit="true"

rdll_size=100

artifactkit_stack_spoof="true"
artifactkit_technique="mailslot"
artifactkit_stage_size=424948
artifactkit_syscalls_method="indirect_randomized"

sleepmask_sleep_method="WaitForSingleObject"
sleepmask_mask_text_section="true"
sleepmask_syscalls_method="indirect_randomized"
```

2. Compile arsenal kit `./build_arsenal_kit.sh`
3. Load `bin/elusiveMice.cna` script into your Cobalt Strike
4. Generate your beacon via `Attacks -> Packages -> Windows Stageless Payload` or any other sort of Beacon's shellcode.
5. (Optionally) observe output in `View -> Script Console`

The CNA script may have `$debug` mode enabled by flipping the variable:

```
# Enable Debug of PE content
# The generated PE content will be displayed in the script console if debug is true

#$debug = "true";
$debug = "true";
```

Which will dump PE headers of newly generated Reflective DLL containing Beacon's codebase.

## Other work

So far there aren't many publicly available implementations of _User-Defined Reflective Loaders_, but the ones of a great quality that I'm aware of include:

- [boku7's BokuLoader](https://github.com/boku7/BokuLoader)


## Author

```   
   Mariusz B. / mgeeky, 21-23
   <mb [at] binary-offensive.com>
   (https://github.com/mgeeky)
```
