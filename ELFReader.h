#pragma once

#include <cstdint>

using namespace std;

using Elf32_Addr = uint32_t;
using Elf32_Off = uint32_t;
using Elf32_Half = uint16_t;
using Elf32_Word = uint32_t;
using Elf32_Sword = int32_t;

using Elf64_Addr = uint64_t;
using Elf64_Off = uint64_t;
using Elf64_Half = uint16_t;
using Elf64_Word = uint32_t;
using Elf64_Sword = int32_t;
using Elf64_Xword = uint64_t;
using Elf64_Sxword = int64_t;

#define EI_NIDENT	16

typedef struct elf64_hdr {
    unsigned char e_indet[EI_NIDENT];//ELF�ļ�����������һ��16�ֽڵı�ʶ��������ǰ�ļ������ݸ�ʽ��λ����[16B]
    Elf64_Half e_type;//�ļ��ı�ʶ�ֶα�ʶ�ļ������ͣ������ִ���ļ�������Ŀ���ļ�[2B]
    Elf64_Half e_machine;//Ŀ���ļ�����ϵ�ṹ(�������ܹ�)[2B]
    Elf64_Half e_version;//��ǰ�ļ��İ汾[2B]

    Elf64_Addr e_entry;//�����������ڵ�ַ[8B]
    Elf64_Off  e_phoff;//����ͷ���ƫ�Ƶ�ַ[8B]
    Elf64_Off  e_shoff;//�α�/�ڱ��ƫ��[8B]

    Elf64_Word e_flags; //��������صı�־λ[4B]
    Elf64_Half e_ehsize; //ELF�ļ�ͷ�Ĵ�С[2B]

    Elf64_Half e_phentsize;//����ͷ��ĵ����С[2B]
    Elf64_Half e_phnum;//����ͷ��ĵ�����Ŀ[2B]

    Elf64_Half e_shentsize;//�ڱ��е���Ĵ�С[2B]
    Elf64_Half e_shnum;//�ڱ��е������Ŀ[2B]
    Elf64_Half e_shstrndx;//�ڱ��н���������[2B]------- �洢�����ƣ����������н�ͷ�����֣��� .text, .data, .bss, �ȵȡ�
}Elf64_hdr;

typedef struct elf64_phdr {
    Elf64_Word p_type;//��ǰSegment������[4B]
    Elf64_Word p_flags;//����صı�־[4B]
    Elf32_Off  p_offset;//��ǰ��������ļ���ʼλ�õ�ƫ����;[4B]
    Elf64_Addr      p_vaddr;//�εĵ�һ���ֽڽ���ӳ�䵽���ڴ��е������ַ[8B]
    Elf64_Addr      p_paddr;//�˳�Ա�������������ַ��ص�ϵͳ�С���Ϊ System V ��������Ӧ�ó���������ַ��Ϣ�����ֶζ����ִ���ļ��͹���Ŀ���ļ����Ծ���������ָ���ģ�[8B]
    Elf64_Xword     p_filesz;//�����ļ�ӳ������ռ���ֽ���[8B]
    Elf64_Xword     p_memsz;//�����ڴ�ӳ����ռ�õ��ֽ���
    Elf64_Xword     p_align;//�����ļ��к��ڴ�����ζ���
}Elf64_Phdr;

typedef struct elf64_shrd {
    Elf64_Word sh_name;//���������ַ������е�����
    Elf64_Word sh_type;//�ڵ����ͺ�����
    Elf64_Xword sh_flags;//1bitλ�ı�־λ

    Elf64_Addr sh_addr;//�����ǰ����Ҫ��װ�ص��ڴ棬��ǰ��洢��ǰ��ӳ�䵽�ڴ���׵�ַ������Ӧ��Ϊ0��[8B]
    Elf64_Off  sh_offset;//��ǰ�ڵ��׵�ַ������ļ���ƫ�ƣ�[8B]
    Elf64_Xword sh_size;//�ڵĴ�С[8B]

    Elf64_Word sh_link;//[4B]���ű�.symtab �� .dynsym��
    //��;��sh_link ��ʾ���ű�������ַ�����Ľ�ͷ��������
    //    ԭ�򣺷��ű��е�ÿ���������洢���ַ������У��� sh_link ָ����ַ�����Ľڡ�
    Elf64_Word sh_info;//�ڵĸ�����Ϣ�������ض��Ľ����ض��ĺ��壬����Ϊ0��[4B]
    Elf64_Xword sh_addralign;//��ַԼ�����룬ֵӦ��Ϊ0����2���ݴη���0��1��ʾδ���ж��룻[8B]
    Elf64_Xword sh_entsize;//����ýڰ���һ�����������ű��ض�λ��ȣ���sh_entsize ��ʾ����ÿ����Ŀ�Ĵ�С�����ֽ�Ϊ��λ����
    //����ýڲ���һ���������.text �ڣ���sh_entsize ͨ������Ϊ 0����Ϊ��Щ�ڲ�����Ŀ���������ݶ�������š�

}Elf64_Shdr;

//���ű�
typedef struct
{
    Elf64_Word st_name; /* Symbol name */
    unsigned char st_info; /* Type and Binding attributes *///���ŵ����ͺ�����, ��4bit��ʶ�˷��Ű�(symbol binding), ��4bit��ʶ�˷�������(symbol type), ��ɷ�����Ϣ(symbol information)
    unsigned char st_other; /* Reserved */
    Elf64_Half st_shndx; /* Section table index���ڱ�ʾ�������ڵĶΣ�Section������ */
    Elf64_Addr st_value; /* Symbol value */
    Elf64_Xword st_size; /* Size of object (e.g., common) */
} Elf64_Sym;

//�ض�λ��
typedef struct
{
    Elf64_Addr r_offset; /* ���õ�ַ����Ҫ�ض�λ��λ�ã� */
    Elf64_Xword r_info;  /* �����������ض�λ���ͣ�������Ϣ�� */
}Elf64_Rel;
typedef struct
{
    Elf64_Addr r_offset;     /* ���õ�ַ����Ҫ�ض�λ��λ�ã� */
    Elf64_Xword r_info;      /* �����������ض�λ���ͣ�������Ϣ�� */
    Elf64_Sxword r_addend;   /* ���ʽ�еĳ������� */
}Elf64_Rela;


//�ṩ��̬����������Ҫ����Ϣ,
typedef struct
{
    Elf64_Sxword d_tag;
    union {
        Elf64_Xword d_val;
        Elf64_Addr d_ptr;
    } d_un;
} Elf64_Dyn;
extern Elf64_Dyn _DYNAMIC[];