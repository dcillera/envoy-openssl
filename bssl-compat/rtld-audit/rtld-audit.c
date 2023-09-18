       #include <string.h>
       #include <link.h>
       #include <stdio.h>
 //      #include "bits/link_lavcurrent.h"

#define LAV_CURRENT 2
       unsigned int
       la_version(unsigned int version)
       {
           printf("la_version(): version = %u; LAV_CURRENT = %u\n",
                   version, LAV_CURRENT);

           return LAV_CURRENT;
       }

       char *
       la_objsearch(const char *name, uintptr_t *cookie, unsigned int flag)
       {
           printf("la_objsearch(): name = %s; cookie = %p", name, cookie);
#ifdef __USE_GNU
           printf("; flag = %s\n",
                   (flag == LA_SER_ORIG) ?    "LA_SER_ORIG" :
                   (flag == LA_SER_LIBPATH) ? "LA_SER_LIBPATH" :
                   (flag == LA_SER_RUNPATH) ? "LA_SER_RUNPATH" :
                   (flag == LA_SER_DEFAULT) ? "LA_SER_DEFAULT" :
                   (flag == LA_SER_CONFIG) ?  "LA_SER_CONFIG" :
                   (flag == LA_SER_SECURE) ?  "LA_SER_SECURE" :
                   "???");
#else
           printf("; flag = %s\n",
                   (flag == 0x01) ?    "LA_SER_ORIG" :
                   (flag == 0x02) ? "LA_SER_LIBPATH" :
                   (flag == 0x04) ? "LA_SER_RUNPATH" :
                   (flag == 0x40) ? "LA_SER_DEFAULT" :
                   (flag == 0x08) ?  "LA_SER_CONFIG" :
                   (flag == 0x80) ?  "LA_SER_SECURE" :
                   "???");
#endif
           return(char *) name;
       }

       void
       la_activity (uintptr_t *cookie, unsigned int flag)
       {
           printf("la_activity(): cookie = %p; flag = %s\n", cookie,
                   (flag == RT_CONSISTENT) ? "LA_ACT_CONSISTENT" :
                   (flag == RT_ADD) ?        "LA_ACT_ADD" :
                   (flag == RT_DELETE) ?     "LA_ACT_DELETE" :
                   "???");
       }

       unsigned int
       la_objopen(struct link_map *map, /*Lmid_t*/ long int lmid, uintptr_t *cookie)
       {
#ifdef __USE_GNU
           printf("la_objopen(): loading \"%s\"; lmid = %s; cookie=%p\n",
                   map->l_name,
                   (lmid == LM_ID_BASE) ?  "LM_ID_BASE" :
                   (lmid == LM_ID_NEWLM) ? "LM_ID_NEWLM" :
                   "???",
#else
           printf("la_objopen(): loading \"%s\"; lmid = %s; cookie=%p\n",
                   map->l_name,
                   (lmid == 0) ?  "LM_ID_BASE" :
                   (lmid == -1) ? "LM_ID_NEWLM" :
                   "???",
#endif
                   cookie);
	   if(!strcmp("/usr/lib64/libcrypto.so", map->l_name) ||
	      !strcmp("/usr/lib64/libssl.so", map->l_name))
	   {
	   //printf("la_objopen(): AUDIT ON\n");
#ifdef __USE_GNU
           return LA_FLG_BINDTO | LA_FLG_BINDFROM;
#else
	   return 0x03;
#endif
	   }
	   else
	   {
	   //printf("la_objopen(): AUDIT OFF\n");
		   return 3;
	   }
       }

       unsigned int
       la_objclose (uintptr_t *cookie)
       {
           printf("la_objclose(): %p\n", cookie);

           return 0;
       }

       void
       la_preinit(uintptr_t *cookie)
       {
           printf("la_preinit(): %p\n", cookie);
       }

       uintptr_t
       la_symbind32(Elf32_Sym *sym, unsigned int ndx, uintptr_t *refcook,
               uintptr_t *defcook, unsigned int *flags, const char *symname)
       {
           printf("la_symbind32(): symname = %s; sym->st_value = %u\n",
                   symname, sym->st_value);
           printf("        ndx = %u; flags = %#x", ndx, *flags);
           printf("; refcook = %p; defcook = %p\n", refcook, defcook);

           return sym->st_value;
       }

       uintptr_t
       la_symbind64(Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook,
               uintptr_t *defcook, unsigned int *flags, const char *symname)
       {
           printf("la_symbind64(): symname = %s; sym->st_value = %lu\n",
                   symname, sym->st_value);
           printf("        ndx = %u; flags = %#x", ndx, *flags);
           printf("; refcook = %p; defcook = %p\n", refcook, defcook);

           return sym->st_value;
       }
#if 0
       Elf32_Addr
       la_i86_gnu_pltenter(Elf32_Sym *sym, unsigned int ndx,
               uintptr_t *refcook, uintptr_t *defcook, La_i86_regs *regs,
               unsigned int *flags, const char *symname, long *framesizep)
       {
           printf("la_i86_gnu_pltenter(): %s (%p)\n", symname, sym->st_value);

           return sym->st_value;
       }
#endif
