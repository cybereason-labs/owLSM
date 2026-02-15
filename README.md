<p align="center">
  <img width="525" height="150" alt="owLSM_logo-Photoroom" src="docs/owLSM_logo-Photoroom.png" />
  <br><br>
  🛡️ <i>Transform linux protection with real prevention capabilities</i> 🛡️
  <br><br>
  <a href="https://discord.gg/gQk5Jxd6vs"><img src="https://img.shields.io/discord/1467824033188941952?label=Discord&logo=discord&style=flat-square" alt="Discord"></a>
  <a href="AGENTS.md"><img src="https://img.shields.io/badge/AI%20Agents-Friendly-blueviolet?style=flat-square" alt="Agent Friendly"></a>
</p>

**owLSM** aspires to become the gold standard for prevention and detection on Linux systems.  
While projects like Sysdig and others excel at tracing and observability, real and scalable **inline prevention** remains an unsolved challenge.  
Using eBPF LSM hooks, owLSM brings powerful, rules-based protection directly into the kernel.  
We focus on:
- Implementing sigma rules engine in the kernel
- Enriching events and rules with context important for defenders 
- Features designed around needs of real security teams  

Help us grow and protect the world by giving us a ⭐ 
 <br><br>
> **Cloud support will come in the future**


## How to build

```bash
# Build the Docker image (one-time setup):
docker build -t owlsm-ci-ubuntu20 .

# Start the build container
docker run -it --rm -v "$PWD":/workspace -w /workspace owlsm-ci-ubuntu20 bash

# Build owLSM
make -j$(nproc)

# Build unit tests
make test -j$(nproc)

# Exit container, can't run owlsm or the tests inside the docker
exit
```

## Run owLSM

Do this outside the docker
```bash
cd build/owlsm/bin

# run without config 
./owlsm 

# run with config 
./owlsm -c /config/path.json

# run with config and excluded pid's (usually we want to exclude parent processes)
./owlsm -c /path/to/config.json -e 123 -e 456
```

## Config and rules
See [Rules/README.md](Rules/README.md)

## Run Unit Tests

```bash
cd build/unit_tests/bin

# Run the unit tests
./unit_tests
```

## Automation Tests (Integration Testing)
See [src/Tests/Automation/README.md](src/Tests/Automation/README.md) for running the automation tests.

# Join the community 
To get involved with the owLSM project visit our [discord](https://discord.gg/gQk5Jxd6vs).  
If you have any questions please ask them on the discord or open a relevant issue.

## Contributers 
We're thrilled that you're interested in contributing to owLSM!  
Please check [CONTRIBUTING.md](.github/CONTRIBUTING.md) to know about the rules, conventions and even **cool AI tools and agents** that will help you a lot!

## License

owLSM is licensed under the **GNU General Public License v2.0** (GPL-2.0).

### Third-Party Libraries

This project includes several third-party libraries with their own licenses
(all GPL-compatible). See [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES) for
details.
