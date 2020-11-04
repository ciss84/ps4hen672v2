#include <ps4.h>

#include "defines.h"
#include "debug.h"
#include "offsets.h"

#define PS4_UPDATE_FULL_PATH "/update/PS4UPDATE.PUP"
#define PS4_UPDATE_TEMP_PATH "/update/PS4UPDATE.PUP.net.temp"

extern char kpayload[];
unsigned kpayload_size;

int install_payload(struct thread *td, struct install_payload_args* args)
{
	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;
	uint8_t* kernel_base = (uint8_t*)(__readmsr(0xC0000082) - XFAST_SYSCALL_addr);
  *(unsigned char*)(kernel_base + 0x1BD800D) = 0x82;
  void(*sceSblSrtcClearTimeDifference)(uint64_t) = (void*)(kernel_base + 0x650930);
	void(*sceSblSrtcSetTime)(uint64_t) = (void*)(kernel_base + 0x6512E0);
	sceSblSrtcClearTimeDifference(15);
	sceSblSrtcSetTime(14861963);
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 = (void**)&kernel_ptr[PRISON0_addr];
	void** got_rootvnode = (void**)&kernel_ptr[ROOTVNODE_addr];
	void (*pmap_protect)(void * pmap, uint64_t sva, uint64_t eva, uint8_t pr) = (void *)(kernel_base + pmap_protect_addr);
	void *kernel_pmap_store = (void *)(kernel_base + PMAP_STORE_addr);
	uint8_t* payload_data = args->payload_info->buffer;
	size_t payload_size = args->payload_info->size;
	struct payload_header* payload_header = (struct payload_header*)payload_data;
	uint8_t* payload_buffer = (uint8_t*)&kernel_base[DT_HASH_SEGMENT_addr];
	if (!payload_data || payload_size < sizeof(payload_header) || payload_header->signature != 0x5041594C4F414458ull)
		return -1;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
  fd->fd_rdir = fd->fd_jdir = *got_rootvnode;
		
	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceRemotePlay = (uint64_t *)(((char *)td_ucred) + 88);
	*sceRemotePlay = 0x3800000000000019; // SceRemotePlay
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceOSUPDATE = (uint64_t *)(((char *)td_ucred) + 88);
	*sceOSUPDATE = 0x3801000000000024; // sceOSUPDATE
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *scevtr = (uint64_t *)(((char *)td_ucred) + 88);
	*scevtr = 0x3800800000000002; // scevtr

	// sceSblACMgrGetDeviceAccessType
	uint64_t *NPXS20103 = (uint64_t *)(((char *)td_ucred) + 88);
	*NPXS20103 = 0x3800000000000011; // NPXS20103
	
	// sceSblACMgrIsAllowedToUseUNK_PFS
	uint64_t *UNK_PFS = (uint64_t *)(((char *)td_ucred) + 88);
	*UNK_PFS = 0x380100000000000A; // UNK_PFS

	// sceSblACMgrIsAllowedToUseUNK_ICC
	uint64_t *UNK_ICC = (uint64_t *)(((char *)td_ucred) + 88);
	*UNK_ICC = 0x3800800000000024; // UNK_ICC
	
	// sceSblACMgrIsAllowedToUsePupUpdate0
	uint64_t *PupUpdate0 = (uint64_t *)(((char *)td_ucred) + 88);
	*PupUpdate0 = 0x3800100000000001; // PupUpdate0
	
	// sceSblACMgrIsAllowedToUseSecureWebProcess
	uint64_t *SecureWebProcess = (uint64_t *)(((char *)td_ucred) + 88);
	*SecureWebProcess = 0x3800000010000003; // SecureWebProcess
	
	// sceSblACMgrIsAllowedToUseSceNKWebProcess
	uint64_t *SceNKWebProcess = (uint64_t *)(((char *)td_ucred) + 88);
	*SceNKWebProcess = 0x3800000000010003; // SceNKWebProcess

	// sceSblACMgrIsAllowedToUseSecureUIProcess
	uint64_t *SecureUIProcess = (uint64_t *)(((char *)td_ucred) + 88);
	*SecureUIProcess = 0x3800000000000033; // SecureUIProcess
	
	// sceSblACMgrIsAllowedToUseSceNKUIProcess
	uint64_t *SceNKUIProcess = (uint64_t *)(((char *)td_ucred) + 88);
	*SceNKUIProcess = 0x380000000000003c; // SceNKUIProcess
	
	// sceSblACMgrIsAllowedToUseSceSysAvControl
	uint64_t *SceSysAvControl = (uint64_t *)(((char *)td_ucred) + 88);
	*SceSysAvControl = 0x380000000000001; // SceSysAvControl

	// sceSblACMgrIsAllowedToUseSceShellUI
	uint64_t *SceShellUI = (uint64_t *)(((char *)td_ucred) + 88);
	*SceShellUI = 0x380000000000000f; // SceShellUI

	// sceSblACMgrIsAllowedToUseSceShellCore
	uint64_t *SceShellCore = (uint64_t *)(((char *)td_ucred) + 88);
	*SceShellCore = 0x3800000000000010; // SceShellCore

	// sceSblACMgrIsAllowedToUseDecid
	uint64_t *Decid = (uint64_t *)(((char *)td_ucred) + 88);
	*Decid = 0x3800000000010003; // Decid

	// sceSblACMgrGetDeviceSceVdecProxy
	uint64_t *SceVdecProxy = (uint64_t *)(((char *)td_ucred) + 88);
	*SceVdecProxy = 0x3800000000000003; // SceVdecProxy

	// sceSblACMgrGetDeviceSceVencProxy
	uint64_t *SceVencProxy = (uint64_t *)(((char *)td_ucred) + 88);
	*SceVencProxy = 0x3800000000000004; // SceVencProxy
	
	// sceSblACMgrGetDeviceOrbisaudiod
	uint64_t *Orbisaudiod = (uint64_t *)(((char *)td_ucred) + 88);
	*Orbisaudiod = 0x3800000000000005; // Orbisaudiod
	
	// sceSblACMgrGetDeviceCoredump
	uint64_t *Coredump = (uint64_t *)(((char *)td_ucred) + 88);
	*Coredump = 0x3800000000000006; // Coredump

	// sceSblACMgrGetDeviceOrbissetip
	uint64_t *Orbissetip = (uint64_t *)(((char *)td_ucred) + 88);
	*Orbissetip = 0x3800000000000008; // Orbissetip

	// sceSblACMgrIsAllowedToUseGnmCompositor
	uint64_t *GnmCompositor = (uint64_t *)(((char *)td_ucred) + 88);
	*GnmCompositor = 0x3800000000000009; // GnmCompositor

	// sceSblACMgrIsAllowedToUseSceGameLiveStreaming
	uint64_t *SceGameLiveStreaming = (uint64_t *)(((char *)td_ucred) + 88);
	*SceGameLiveStreaming = 0x3800000000000012; // SceGameLiveStreaming
	
	// sceSblACMgrIsAllowedToUseSCE_SYS_SERVICES
	uint64_t *SCE_SYS_SERVICES = (uint64_t *)(((char *)td_ucred) + 88);
	*SCE_SYS_SERVICES = 0x3800000000010003; // SCE_SYS_SERVICES
	
	// sceSblACMgrIsAllowedToUseScePartyDaemon
	uint64_t *ScePartyDaemon = (uint64_t *)(((char *)td_ucred) + 88);
	*ScePartyDaemon = 0x3800000000000014; // ScePartyDaemon

	// sceSblACMgrIsAllowedToUseSceAvCapture
	uint64_t *SceAvCapture = (uint64_t *)(((char *)td_ucred) + 88);
	*SceAvCapture = 0x3800000000000015; // SceAvCapture
	
	// sceSblACMgrIsAllowedToUseSceVideoCoreServer
	uint64_t *SceVideoCoreServer = (uint64_t *)(((char *)td_ucred) + 88);
	*SceVideoCoreServer = 0x3800000000000016; // SceVideoCoreServer	

	// sceSblACMgrIsAllowedToUsemini_syscore
	uint64_t *mini_syscore = (uint64_t *)(((char *)td_ucred) + 88);
	*mini_syscore = 0x3800000000000022; // mini_syscore

	// sceSblACMgrIsAllowedToUseSceCloudClientDaemon
	uint64_t *SceCloudClientDaemon = (uint64_t *)(((char *)td_ucred) + 88);
	*SceCloudClientDaemon = 0x3800000000000028; // SceCloudClientDaemon
	
	// sceSblACMgrIsAllowedToUsefs_cleaner
	uint64_t *fs_cleaner = (uint64_t *)(((char *)td_ucred) + 88);
	*fs_cleaner = 0x380000000000001d; // fs_cleaner	

	// sceSblACMgrIsAllowedToUseSceSocialScreenMgr
	uint64_t *SceSocialScreenMgr = (uint64_t *)(((char *)td_ucred) + 88);
	*SceSocialScreenMgr = 0x3800000000000037; // SceSocialScreenMgr

	// sceSblACMgrIsAllowedToUseSceSpZeroConf
	uint64_t *SceSpZeroConf = (uint64_t *)(((char *)td_ucred) + 88);
	*SceSpZeroConf = 0x380000001000000E; // SceSpZeroConf

	// sceSblACMgrIsAllowedToUseSceMusicCoreServer
	uint64_t *SceMusicCoreServer = (uint64_t *)(((char *)td_ucred) + 88);
	*SceMusicCoreServer = 0x380000000000001a; // SceMusicCoreServer

	// sceSblACMgrIsAllowedToUsesceSblACMgrHasUseHp3dPipeCapability
	uint64_t *sceSblACMgrHasUseHp3dPipeCapability = (uint64_t *)(((char *)td_ucred) + 88);
	*sceSblACMgrHasUseHp3dPipeCapability = 0x3800000010000009; // sceSblACMgrHasUseHp3dPipeCapability

	// sceSblACMgrIsAllowedToUsesceSblACMgrHasUseHp3dPipeCapability2
	uint64_t *sceSblACMgrHasUseHp3dPipeCapability2 = (uint64_t *)(((char *)td_ucred) + 88);
	*sceSblACMgrHasUseHp3dPipeCapability2 = 0x380100000000002C; // sceSblACMgrHasUseHp3dPipeCapability2
	
	// sceSblACMgrIsAllowedToUseSceSysCore
	uint64_t *SceSysCore = (uint64_t *)(((char *)td_ucred) + 88);
	*SceSysCore = 0x3800000000000007; // SceSysCore	
				
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);
	
  uint8_t *kmem;
  //panic
 	kmem = (uint8_t *)(kernel_base + 0x002ED33A);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
	kmem[4] = 0x90;
	
  // Patch setuid: Don't run kernel exploit more than once/privilege escalation
	kmem = (uint8_t *)(kernel_base + 0x0010BED0);
	kmem[0] = 0xB8;
	kmem[1] = 0x00;
	kmem[2] = 0x00;
	kmem[3] = 0x00;
	kmem[4] = 0x00;
	kmem = (uint8_t *)(kernel_base + global_settings_base);
	kmem[0x36] |= 0x14;
	kmem[0x59] |= 0x01;
	kmem[0x59] |= 0x02;
	kmem[0x5A] |= 0x01;
	kmem[0x78] |= 0x01;
	
	// debug menu error patches
	*(uint32_t *)(kernel_base + debug_menu_error_patch1) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch2) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch3) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch4) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch5) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch6) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch7) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch8) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch9) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch10) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch11) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch12) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch13) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch14) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch15) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch16) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch17) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch18) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch19) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch20) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch21) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch22) = 0;
	*(uint32_t *)(kernel_base + debug_menu_error_patch23) = 0;
	
	// flatz disable pfs signature check
	*(uint32_t *)(kernel_base + disable_signature_check_patch) = 0x90C3C031;
	*(uint32_t *)(kernel_base + sys_dynlib_dlsym_patch2) = 0x90C3C031;
	*(uint32_t *)(kernel_base + sys_map) = 0x37B64037;	
	*(uint32_t *)(kernel_base) = 0x464C457F;
  
  // unprivileged_user
	kmem = (uint8_t *)(kernel_base + sys_mount_unprivileged_user);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
	kmem[4] = 0x90;  
	kmem[5] = 0x90;
	
	*(uint32_t *)(kernel_base + sys_vm_fault_patchA) = 0x90909090;
	*(uint16_t *)(kernel_base + sys_vm_fault_patchB) = 0x9090;  

	// sys_rwx_patch
	kmem = (uint8_t *)(kernel_base + sys_rwx_patch);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
	kmem[4] = 0x90;
  kmem[5] = 0x90;
	      
  *(uint16_t*)(kernel_base + sys_patchA) = 0x9090;  
  *(uint16_t*)(kernel_base + sys_patchB) = 0x9090;
	    		  		   
	// flatz enable debug RIFs	
	*(uint32_t *)(kernel_base + enable_debug_rifs_patch1) = 0x90C301B0;
	*(uint32_t *)(kernel_base + enable_debug_rifs_patch2) = 0x90C301B0;
   			
	// flatz allow sys_dynlib_dlsym in all processes 6.72
	*(uint64_t*)(kernel_base + sys_dynlib_dlsym_patchA) = 0x8B4890000001C7E9;
		
	// dynlib_do_dlsym
	kmem = (uint8_t *)(kernel_base + sys_dynlib_dlsym_patchB);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
	kmem[4] = 0x90;
	kmem[5] = 0x90;
		
	// Enable rwx mapping in kmem_alloc
	kmem = (uint8_t *)(kernel_base + 0x002507F5);
	kmem[0] = 0x07;
	kmem = (uint8_t *)(kernel_base + 0x00250803);
	kmem[0] = 0x07;
	
	// Patch copyin/copyout to allow userland + kernel addresses in both params
	// copyin
	kmem = (uint8_t *)(kernel_base + 0x003C17F7);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem = (uint8_t *)(kernel_base + 0x003C1803);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;

	// copyout
	kmem = (uint8_t *)(kernel_base + 0x003C1702);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem = (uint8_t *)(kernel_base + 0x003C170E);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	
	// Patch copyinstr
	kmem = (uint8_t *)(kernel_base + 0x003C1CA3);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem = (uint8_t *)(kernel_base + 0x003C1CAF);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
  
	// ptrace_patches
	kmem = (uint8_t *)(kernel_base + 0x0010F892);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem[2] = 0x90;
	kmem[3] = 0x90;
	kmem[4] = 0x90;
  kmem[5] = 0x90;
	// ptrace2_patches
	kmem = (uint8_t *)(kernel_base + 0x0010FD22);
	kmem[0] = 0xE9;
	kmem[1] = 0xE2;
	kmem[2] = 0x02;
	kmem[3] = 0x00;
	kmem[4] = 0x00;
    
	// CLOCK_patches
	kmem = (uint8_t *)(kernel_base + 0x00123280);
	kmem[0] = 0x55;
	kmem[1] = 0x48;
	kmem[2] = 0x89;
	kmem[3] = 0xE5;
	kmem[4] = 0x53;
  kmem[5] = 0x48;
	kmem[6] = 0x83;
	kmem[7] = 0xEC;
	kmem[8] = 0x58;
	kmem[9] = 0x48;
	kmem[10] = 0x8D;
  kmem[11] = 0x1D;
	
	// JOGolden
	kmem = (uint8_t *)(kernel_base + 0x003C1AC2);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	kmem = (uint8_t *)(kernel_base + 0x003C1AD1);
	kmem[0] = 0x90;
	kmem[1] = 0x90;
	
	// Patch memcpy stack
	kmem = (uint8_t *)(kernel_base + 0x003C15BD);
	kmem[0] = 0xEB;
		  
	// spoof sdk_version - enable vr
	*(uint32_t *)(kernel_base + sdk_version_patch) = FAKE_FW_VERSION;
	*(uint32_t *)(kernel_base + sdk_version_patch1) = FAKE_FW_VERSION;
	*(uint32_t *)(kernel_base + sdk_version_patch2) = FAKE_FW_VERSION;
	*(uint32_t *)(kernel_base + sdk_version_patch3) = FAKE_FW_VERSION;
	*(uint32_t *)(kernel_base + sdk_version_patch4) = FAKE_FW_VERSION;
	*(uint32_t *)(kernel_base + sdk_version_patch5) = FAKE_FW_VERSION;
	*(uint32_t *)(kernel_base + sdk_version_patch6) = FAKE_FW_VERSION;
	*(uint32_t *)(kernel_base + sdk_version_patch7) = FAKE_FW_VERSION;
	*(uint32_t *)(kernel_base + sdk_version_patch8) = FAKE_FW_VERSION;
	*(uint32_t *)(kernel_base + sdk_version_patch9) = FAKE_FW_VERSION;
	// spoof sdk_version v2
	*(uint64_t *)(kernel_base + sdk_version2_patch1) = FAKE_FW2_VERSION;
	*(uint64_t *)(kernel_base + sdk_version2_patch2) = FAKE_FW2_VERSION;
	*(uint64_t *)(kernel_base + sdk_version2_patch3) = FAKE_FW2_VERSION;
	*(uint64_t *)(kernel_base + sdk_version2_patch4) = FAKE_FW2_VERSION;
	*(uint64_t *)(kernel_base + sdk_version2_patch5) = FAKE_FW2_VERSION;
	*(uint64_t *)(kernel_base + sdk_version2_patch6) = FAKE_FW2_VERSION;
	// spoof sdk_version v3
  *(uint32_t *)(kernel_base + sdk_version3_patch1) = FAKE_FW0_VERSION_SDK;
 	*(uint32_t *)(kernel_base + sdk_version3_patch2) = FAKE_FW1_VERSION_SDK;
 	*(uint32_t *)(kernel_base + sdk_version3_patch3) = FAKE_FW2_VERSION_SDK;
 	*(uint32_t *)(kernel_base + sdk_version3_patch4) = FAKE_FW3_VERSION_SDK;

	// spoof version
	/**(uint32_t *)(kernel_base + sdk_version4_patch) = FAKE_FWV_VERSION;
	*(uint32_t *)(kernel_base + sdk_version4_patch1) = FAKE_FWV_VERSION;
	*(uint32_t *)(kernel_base + sdk_version4_patch2) = FAKE_FWV_VERSION;
	*(uint32_t *)(kernel_base + sdk_version4_patch3) = FAKE_FWV_VERSION;
	*(uint32_t *)(kernel_base + sdk_version4_patch4) = FAKE_FWV_VERSION;
	*(uint32_t *)(kernel_base + sdk_version4_patch5) = FAKE_FWV_VERSION;
	*(uint32_t *)(kernel_base + sdk_version4_patch6) = FAKE_FWV_VERSION;
	*(uint32_t *)(kernel_base + sdk_version4_patch7) = FAKE_FWV_VERSION;*/
	 		 	 		 	 				
	// enable debug log
	*(uint16_t*)(kernel_base + enable_debug_log_patch) = 0x3BEB;

	// enable uart output
	*(uint32_t *)(kernel_base + enable_uart_patch) = 0;
  	
	// install kpayload
	memset(payload_buffer, 0, PAGE_SIZE);
	memcpy(payload_buffer, payload_data, payload_size);
	
  uint64_t sss = ((uint64_t)payload_buffer) & ~(uint64_t)(PAGE_SIZE-1);
	uint64_t eee = ((uint64_t)payload_buffer + payload_size + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE-1);
	kernel_base[pmap_protect_p_addr] = 0xEB;
	pmap_protect(kernel_pmap_store, sss, eee, 7);
	kernel_base[pmap_protect_p_addr] = 0x75;

	// Restore write protection
	writeCr0(cr0);

	int (*payload_entrypoint)();
	*((void**)&payload_entrypoint) = (void*)(&payload_buffer[payload_header->entrypoint_offset]);

	return payload_entrypoint();
}

static inline void patch_update(void)
{
	unlink(PS4_UPDATE_FULL_PATH);
	unlink(PS4_UPDATE_TEMP_PATH);

	mkdir(PS4_UPDATE_FULL_PATH, 0777);
	mkdir(PS4_UPDATE_TEMP_PATH, 0777);
}

int _main(struct thread *td) 
{
	int result;

	initKernel();
	initLibc();

#ifdef DEBUG_SOCKET
	initNetwork();
	initDebugSocket();
#endif

	printfsocket("Starting...\n");

	struct payload_info payload_info;
	payload_info.buffer = (uint8_t *)kpayload;
	payload_info.size = (size_t)kpayload_size;

	errno = 0;

	result = kexec(&install_payload, &payload_info);
	result = !result ? 0 : errno;
	printfsocket("install_payload: %d\n", result);

	patch_update();

	initSysUtil();
	notify("Mugiwara_Hen-U SP-"VERSION);

	printfsocket("Done.\n");

#ifdef DEBUG_SOCKET
	closeDebugSocket();
#endif

	return result;
}