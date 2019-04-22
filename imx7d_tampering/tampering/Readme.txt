# Tampering application demo

## 1. INTRODUCTION
	This application is a Linux user space application, which is a programming example for manipulating the most important SNVS/Tampering registers.
	This demo can be used to demonstrate both static and active tampering for i.MX6UL and i.MX7D processors. 

	 
## 2. BUILD STEPS
	For being able to build the sources, it is needed the right Yocto Toolchain for your board.
	For example, for i.MX7D board, 32-bit arm cortexa7 gnueabi toolchain.
	Building steps are:
	Download the source code for Yocto Project, build a toolchain by running:
		$ bitbake meta-toolchain 
	After that, go in your build directory, and run this .sh:
		$ ./tmp/deploy/sdk/fsl-imx-x11-glibc-x86_64-meta-toolchain-cortexa7hf-neon-toolchain-4.9.11-1.0.0.sh
	After that, chose a directory path for the toolchain, for example "/work/catalin/toolchain"
	After that, each time you want to use the toolchain, use this command:
		$ source /work/catalin/toolchains/environment-setup-cortexa7hf-neon-poky-linux-gnueabi
	After that, you should be able to build your executable by running:
		$ make clean
		$ make PLATFORM=IMX7D

## 3. INSTRUCTIONS
	The tampers and security violations can be configured with this tool and also is possible to view the current configuration.
	The full usage info can be displayed using "tpsv" command.
	The main functions to use are the following:
		=>tpsv showcfg
		=>tpsv get_sv_cfg <source>: Print the configuration of a security violation.
		=>tpsv set_sv_cfg <source> <enable> <policy> <irq_enable>: Configure a security violation.
		=>tpsv get_tp_cfg <tamper>: Display the configuration of a tamper
		=>tpsv set_tp_cfg <tamper> passive <enable> <polarity> <gf_enable> <gf_value>: Configure a passive tamper to compare against a polarity
		=>run secsvconf
		=>run sectpconf
		=>run loadsecconf
	Furthermore, only for i.MX7D:
		=>run set_passive_tamp: Sets registers up for passive tampering 
		=>run set_act_tamp: Sets registers up for active tampering
		=>run check_tamp_status: Checks the configuration of tamper registers
		=>run check_SRTC

		
#### 3.1 Running instruction:
		$ ./tamp
