# JSInterface_analyzer
Analyze APK file for taint analysis targeting Javascript Interface using AppShark


## Used App Shark for taint analysis
https://github.com/bytedance/appshark/tree/main

## How to use
- put apks you want to analyze in the apks directory
- then run the analyze_interface.py
`python3 analyze_interface.py`

- You need to edit `analyze_interface.py` to define Sinks you want to find.
  - Reference below for specific information
    https://github.com/bytedance/appshark/tree/main

## Notice!
- You need to use JDK 11 version to run AppShark
- Reference below for specific information
  https://github.com/bytedance/appshark/tree/main
