#ifndef __OFFSETS_H__
#define __OFFSETS_H__
#pragma once

// 6.72
#define	XFAST_SYSCALL_addr              0x000001C0

// Names - Data
#define PRISON0_addr                    0x0113E518
#define ROOTVNODE_addr                  0x02300320
#define PMAP_STORE_addr                 0x01BB7880
#define DT_HASH_SEGMENT_addr            0x00C00468
#define global_settings_base            0x01BD7FD0

// Functions
#define pmap_protect_addr               0x00050F50
#define pmap_protect_p_addr             0x00050F9C

// Patches
// debug menu error
#define debug_menu_error_patch1         0x00504A94
#define debug_menu_error_patch2         0x00504C77
#define debug_menu_error_patch3         0x00507A01
#define debug_menu_error_patch4         0x00507B09
#define debug_menu_error_patch5         0x00507BB8
#define debug_menu_error_patch6         0x00507ECF
#define debug_menu_error_patch7         0x00508D5C
#define debug_menu_error_patch8         0x00510423
#define debug_menu_error_patch9         0x005108E3
#define debug_menu_error_patch10        0x00510BFA
#define debug_menu_error_patch11        0x005115E1
#define debug_menu_error_patch12        0x00511B4D
#define debug_menu_error_patch13        0x00512002
#define debug_menu_error_patch14        0x00512191
#define debug_menu_error_patch15        0x005140A8
#define debug_menu_error_patch16        0x00514293
#define debug_menu_error_patch17        0x00515E71
#define debug_menu_error_patch18        0x00515EE7
#define debug_menu_error_patch19        0x00515F71
#define debug_menu_error_patch20        0x00515F8D
#define debug_menu_error_patch21        0x0051F123
#define debug_menu_error_patch22        0x002CFBDD
#define debug_menu_error_patch23        0x00B51368

// disable signature check
#define disable_signature_check_patch   0x006A8EB0

// enable debug RIFs
#define enable_debug_rifs_patch1        0x0066AEB0
#define enable_debug_rifs_patch2        0x0066AEE0

// allow sys_dynlib_dlsym in all processes
#define sys_dynlib_dlsym_patch          0x001D895A
// Patch a function called by dynlib_dlsym
#define sys_dynlib_dlsym_patch2         0x0041A2D0
#define sys_map                         0x000AB57A
 
// Patch to remove vm_fault: fault on nofault entry, addr %llx
#define sys_vm_fault_patchA             0x000BC8F6
#define sys_vm_fault_patchB             0x000BC8FA
 
// allow sys_dynlib_dlsym in all processes
#define sys_dynlib_dlsym_patchA         0x001D895A

// flatz allow mangled symbol in dynlib_do_dlsym
#define sys_dynlib_dlsym_patchB         0x00417A27

// Enable mount for unprivileged user
#define sys_mount_unprivileged_user     0x0044026A

// Patch by: JOGolden
#define sys_patchA                      0x003C1AC2
#define sys_patchB                      0x003C1AD1

// Patch to remove vm_fault: fault on nofault entry, addr %llx
#define sys_vm_fault_patch              0x000BC8F6

// patch mprotect to allow RWX (mprotect) mapping 6.72
#define sys_rwx_patch                   0x00451DB8

// sdk version spoof - enable all VR fws
#define sdk_version_patch               0x0044C79B
#define sdk_version_patch1              0x0044D719
#define sdk_version_patch2              0x0044D7BA
#define sdk_version_patch3              0x00666158
#define sdk_version_patch4              0x006A9DB2
#define sdk_version_patch5              0x0077A5B4
#define sdk_version_patch6              0x0078315D
#define sdk_version_patch7              0x01A84248
#define sdk_version_patch8              0x022C0718
#define sdk_version_patch9              0x02926C81
// sdk version spoofv2
#define sdk_version2_patch1             0x027AFC2C
#define sdk_version2_patch2             0x027AFC53
#define sdk_version2_patch3             0x027B0C33
#define sdk_version2_patch4             0x027E10AC
#define sdk_version2_patch5             0x027E10D3
#define sdk_version2_patch6             0x027E20B2
// sdk version spoofv3
#define sdk_version3_patch1             0x007AFDBF
#define sdk_version3_patch2             0x00854B70
#define sdk_version3_patch3             0x00854C4D
#define sdk_version3_patch4             0x00B48982
// sdk version spoofv4
/*#define sdk_version4_patch              0x01AAA759
#define sdk_version4_patch1             0x01AAE709
#define sdk_version4_patch2             0x01ABE995
#define sdk_version4_patch3             0x01AC6BE9
#define sdk_version4_patch4             0x01AD370D 			 		 	 		 	 				
#define sdk_version4_patch5             0x01ADBBD1
#define sdk_version4_patch6             0x01AE7829
#define sdk_version4_patch7             0x01AEFCF9*/
	
// enable debug log
#define enable_debug_log_patch          0x00123367

// enable uart output
#define enable_uart_patch               0x01A6EB18/*0x01570338*/

#endif