#include<fstream>  
#include<iostream>
#include<cstdio> 
#include"ELFReader.cpp"


using namespace std;
#define _CRT_SECURE_NO_WARNINGS
int main() {
    FILE* fp = nullptr;
    errno_t err = fopen_s(&fp, "C:\\Users\\11252\\Desktop����\\libconn.so", "rb");
    if (err != 0 || !fp) {
        perror("Failed to open file");
        return EXIT_FAILURE;
    }
    // ��ȡ ELF �ļ�ͷ
    Elf64_hdr elf64_hdr;

    // ���� ELF �ļ�ͷ
    ElfHeaderParse(fp, &elf64_hdr);

    // ��������ͷ��
    ElfProgramHeaderTableParse(fp, &elf64_hdr);

    // ������ͷ��
    ElfSectionHeaderTableParse(fp, &elf64_hdr);

    //�����ַ�����
   StringTableParse(fp, &elf64_hdr);

   //�������ű�
   SymbolTableParse(fp, &elf64_hdr);

   //�ض�λ
   RelocationTableParse(fp, &elf64_hdr);

   //��̬��
   printDynamicSegment64(fp, &elf64_hdr);


    // �ر��ļ�
    fclose(fp);

    return EXIT_SUCCESS;
	

}