#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <ctype.h>
#include <openssl/sha.h>

#pragma pack(push, 1)
typedef struct DirEntry
{
    unsigned char DIR_Name[11];     // File name
    unsigned char DIR_Attr;         // File attributes
    unsigned char DIR_NTRes;        // Reserved
    unsigned char DIR_CrtTimeTenth; // Created time (tenths of second)
    unsigned short DIR_CrtTime;     // Created time (hours, minutes, seconds)
    unsigned short DIR_CrtDate;     // Created day
    unsigned short DIR_LstAccDate;  // Accessed day
    unsigned short DIR_FstClusHI;   // High 2 bytes of the first cluster address
    unsigned short DIR_WrtTime;     // Written time (hours, minutes, seconds
    unsigned short DIR_WrtDate;     // Written day
    unsigned short DIR_FstClusLO;   // Low 2 bytes of the first cluster address
    unsigned int DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct BootEntry
{
    unsigned char BS_jmpBoot[3];    // Assembly instruction to jump to boot code
    unsigned char BS_OEMName[8];    // OEM Name in ASCII
    unsigned short BPB_BytsPerSec;  // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
    unsigned char BPB_SecPerClus;   // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
    unsigned short BPB_RsvdSecCnt;  // Size in sectors of the reserved area
    unsigned char BPB_NumFATs;      // Number of FATs
    unsigned short BPB_RootEntCnt;  // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
    unsigned short BPB_TotSec16;    // 16-bit value of number of sectors in file system
    unsigned char BPB_Media;        // Media type
    unsigned short BPB_FATSz16;     // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
    unsigned short BPB_SecPerTrk;   // Sectors per track of storage device
    unsigned short BPB_NumHeads;    // Number of heads in storage device
    unsigned int BPB_HiddSec;       // Number of sectors before the start of partition
    unsigned int BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
    unsigned int BPB_FATSz32;       // 32-bit size in sectors of one FAT
    unsigned short BPB_ExtFlags;    // A flag for FAT
    unsigned short BPB_FSVer;       // The major and minor version number
    unsigned int BPB_RootClus;      // Cluster where the root directory can be found
    unsigned short BPB_FSInfo;      // Sector where FSINFO structure can be found
    unsigned short BPB_BkBootSec;   // Sector where backup copy of boot sector is located
    unsigned char BPB_Reserved[12]; // Reserved
    unsigned char BS_DrvNum;        // BIOS INT13h drive number
    unsigned char BS_Reserved1;     // Not used
    unsigned char BS_BootSig;       // Extended boot signature to identify if the next three values are valid
    unsigned int BS_VolID;          // Volume serial number
    unsigned char BS_VolLab[11];    // Volume label in ASCII. User defines when creating the file system
    unsigned char BS_FilSysType[8]; // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

struct BootEntry *entry;

void usage_info()
{
    printf("Usage: ./file_rec disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
}

// Source: https://www.cs.fsu.edu/~cop4610t/lectures/project3/Week11/Slides_week11.pdf

unsigned int fat_entry(char *addr, BootEntry *entry, unsigned int cluster_num)
{
    unsigned int offset = entry->BPB_RsvdSecCnt * entry->BPB_BytsPerSec;
    unsigned int *fat_table = (unsigned int *)(addr + offset);
    unsigned int next_cluster = fat_table[cluster_num];

    if (next_cluster >= 0x0FFFFFF8)
    // checking for EOF
    {
        return 0;
    }
    else
    {
        return next_cluster;
    }
}

int main(int argc, char *argv[])
{

    int opt = 1;
    char option = '\0';
    char *filename;
    char *sha1 = NULL;

    if (argc == 1)
    {
        usage_info();
        return 0;
    }

    int fd = open(argv[1], O_RDWR);
    if (fd == -1)
    {
        usage_info();
        exit(0);
    }

    // Get disk size
    struct stat sb;
    if (fstat(fd, &sb) == -1)
    {
        fprintf(stderr, "Disk cannot be read\n");
        exit(0);
    }

    // Map file into memory
    char *addr = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (addr == MAP_FAILED)
    {
        fprintf(stderr, "Failed to map disk\n");
        exit(0);
    }

    while ((opt = getopt(argc, argv, "ilr:R:s:")) != -1)
    {
        switch (opt)
        {
        case 'i':
            option = 'i';
            break;
        case 'l':
            option = 'l';
            break;
        case 'r':
            option = 'r';
            filename = optarg;
            if (optind < argc && strcmp(argv[optind], "-s") == 0)
            {
                sha1 = argv[optind + 1];
                // printf(sha1);
                optind += 2;
            }
            break;
        default:
            break;
        }
    }

    if (option == 0 || (option == 'r' && filename == NULL))
    {
        usage_info();
        exit(0);
    }

    entry = (BootEntry *)addr;

    if (option == 'r' && sha1 != NULL)
    {
        unsigned int root_cluster = entry->BPB_RootClus;  // Cluster where the root directory can be found
        unsigned int sector_size = entry->BPB_BytsPerSec; // Number of bytes per sector
        unsigned int bytes_per_cluster = entry->BPB_SecPerClus * sector_size;
        int matches = 0;
        DirEntry *matching_entry = NULL;
        unsigned char hash[SHA_DIGEST_LENGTH];

        while (root_cluster != 0) // while not EOF
        {
            unsigned int root_entry = (entry->BPB_RsvdSecCnt + entry->BPB_NumFATs * entry->BPB_FATSz32) * sector_size + (entry->BPB_SecPerClus * (root_cluster - 2)) * sector_size;

            unsigned int num_entries = bytes_per_cluster / sizeof(DirEntry);

            for (unsigned int i = 0; i < num_entries; i++)
            {
                DirEntry *dir_entry = (DirEntry *)(addr + root_entry + i * sizeof(DirEntry));
                if (dir_entry->DIR_Name[0] == 0xe5)
                {
                    char *file_name_deleted = (char *)dir_entry->DIR_Name;
                    char *file_name_cleaned = malloc(strlen(file_name_deleted) + 1);
                    char *p = file_name_cleaned;
                    char *q = file_name_deleted;
                    while (*q != '\0')
                    {
                        if (!isspace((unsigned char)*q))
                        {
                            *p++ = *q;
                        }
                        q++;
                    }
                    *p = '\0';

                    char *new_filename = malloc(strlen(filename));
                    char *p2 = new_filename;
                    char *q2 = filename;

                    while (*q2 != '\0')
                    {
                        if (*q2 != '.')
                        {
                            *p2++ = *q2;
                        }
                        q2++;
                    }
                    *p2 = '\0';

                    if (strcmp(file_name_cleaned + 1, new_filename + 1) == 0)
                    {
                        unsigned int start_cluster = (dir_entry->DIR_FstClusHI << 16) | dir_entry->DIR_FstClusLO;
                        unsigned int byte_address = (entry->BPB_RsvdSecCnt + entry->BPB_NumFATs * entry->BPB_FATSz32 + (start_cluster - 2) * entry->BPB_SecPerClus) * sector_size;
                        unsigned char *file_content = (unsigned char *)(addr + byte_address);
                        
                        SHA1((unsigned char *)(file_content), dir_entry->DIR_FileSize, hash);
                        unsigned char sha1_bytes[SHA_DIGEST_LENGTH];
                        for (int i = 0; i < SHA_DIGEST_LENGTH * 2; i += 2)
                        {
                            char hex[3];
                            hex[0] = sha1[i];
                            hex[1] = sha1[i + 1];
                            hex[2] = '\0';
                            sha1_bytes[i / 2] = strtol(hex, NULL, 16);
                        }
                        if (memcmp(sha1_bytes, hash, SHA_DIGEST_LENGTH) == 0)
                        {
                            matches++;
                            matching_entry = dir_entry;
                        }
                        else
                        {
                            continue;
                        }
                    }
                }
            }
            root_cluster = fat_entry(addr, entry, root_cluster);
        }
        if (matches == 0)
        {
            printf("%s: file not found\n", filename);
        }
        else
        {
            unsigned int num_clusters = (matching_entry->DIR_FileSize + bytes_per_cluster - 1) / bytes_per_cluster;
            if (matching_entry->DIR_FileSize > 0)
            {
                unsigned int current_cluster = (matching_entry->DIR_FstClusHI << 16) | matching_entry->DIR_FstClusLO;

                for (unsigned int i = 0; i < entry->BPB_NumFATs; i++)
                {
                    unsigned int offset = entry->BPB_RsvdSecCnt * entry->BPB_BytsPerSec + i * (entry->BPB_FATSz32 * entry->BPB_BytsPerSec);
                    unsigned int *fat_table = (unsigned int *)(addr + offset);

                    for (unsigned int j = 0; j < num_clusters; j++)
                    {
                        if (j == num_clusters - 1)
                        {
                            fat_table[current_cluster] = 0xFFFFFFFF;
                        }
                        else
                        {
                            fat_table[current_cluster] = current_cluster + 1;
                            current_cluster = current_cluster + 1;
                        }
                    }
                }
            }
            matching_entry->DIR_Name[0] = filename[0];
            printf("%s: successfully recovered with SHA-1\n", filename);
        }
    }

    if (option == 'r' && sha1 == NULL)
    {
        unsigned int root_cluster = entry->BPB_RootClus;  // Cluster where the root directory can be found
        unsigned int sector_size = entry->BPB_BytsPerSec; // Number of bytes per sector
        unsigned int bytes_per_cluster = entry->BPB_SecPerClus * sector_size;
        int matches = 0;
        DirEntry *matching_entry = NULL;

        while (root_cluster != 0) // while not EOF
        {
            unsigned int root_entry = (entry->BPB_RsvdSecCnt + entry->BPB_NumFATs * entry->BPB_FATSz32) * sector_size + (entry->BPB_SecPerClus * (root_cluster - 2)) * sector_size;

            unsigned int num_entries = bytes_per_cluster / sizeof(DirEntry);

            for (unsigned int i = 0; i < num_entries; i++)
            {
                DirEntry *dir_entry = (DirEntry *)(addr + root_entry + i * sizeof(DirEntry));

                if (dir_entry->DIR_Name[0] == 0xe5)
                {
                    char *file_name_deleted = (char *)dir_entry->DIR_Name;
                    char *file_name_cleaned = malloc(strlen(file_name_deleted) + 1);
                    char *p = file_name_cleaned;
                    char *q = file_name_deleted;

                    while (*q != '\0')
                    {
                        if (!isspace((unsigned char)*q))
                        {
                            *p++ = *q;
                        }
                        q++;
                    }
                    *p = '\0';

                    char *new_filename = malloc(strlen(filename));
                    char *p2 = new_filename;
                    char *q2 = filename;

                    while (*q2 != '\0')
                    {
                        if (*q2 != '.')
                        {
                            *p2++ = *q2;
                        }
                        q2++;
                    }
                    *p2 = '\0';

                    if (strcmp(file_name_cleaned + 1, new_filename + 1) == 0)
                    {
                        matches++;
                        if (matches > 1)
                        {
                            printf("%s: multiple candidates found\n", filename);
                            exit(0);
                        }
                        matching_entry = dir_entry;
                    }
                    else
                    {
                        continue;
                    }
                }
            }
            root_cluster = fat_entry(addr, entry, root_cluster);
        }
        if (matches == 0)
        {
            printf("%s: file not found\n", filename);
        }
        else
        {
            unsigned int num_clusters = (matching_entry->DIR_FileSize + bytes_per_cluster - 1) / bytes_per_cluster;
            if (matching_entry->DIR_FileSize > 0)
            {
                unsigned int current_cluster = (matching_entry->DIR_FstClusHI << 16) | matching_entry->DIR_FstClusLO;

                for (unsigned int i = 0; i < entry->BPB_NumFATs; i++)
                {
                    unsigned int offset = entry->BPB_RsvdSecCnt * entry->BPB_BytsPerSec + i * (entry->BPB_FATSz32 * entry->BPB_BytsPerSec);
                    unsigned int *fat_table = (unsigned int *)(addr + offset);

                    for (unsigned int j = 0; j < num_clusters; j++)
                    {
                        if (j == num_clusters - 1)
                        {
                            fat_table[current_cluster] = 0xFFFFFFFF;
                        }
                        else
                        {
                            fat_table[current_cluster] = current_cluster + 1;
                            current_cluster = current_cluster + 1;
                        }
                    }
                }
            }
            matching_entry->DIR_Name[0] = filename[0];
            printf("%s: successfully recovered\n", filename);
        }
    }

    if (option == 'i')
    {
        printf("Number of FATs = %u\n", entry->BPB_NumFATs);
        printf("Number of bytes per sector = %u\n", entry->BPB_BytsPerSec);
        printf("Number of sectors per cluster = %u\n", entry->BPB_SecPerClus);
        printf("Number of reserved sectors = %u\n", entry->BPB_RsvdSecCnt);
    }

    if (option == 'l')
    {
        unsigned int root_cluster = entry->BPB_RootClus;  // Cluster where the root directory can be found
        unsigned int sector_size = entry->BPB_BytsPerSec; // Number of bytes per sector
        unsigned int bytes_per_cluster = entry->BPB_SecPerClus * sector_size;
        unsigned int total_entries = 0; // total number of entries

        while (root_cluster != 0) // while not EOF
        {
            unsigned int root_entry = (entry->BPB_RsvdSecCnt + entry->BPB_NumFATs * entry->BPB_FATSz32) * sector_size + (entry->BPB_SecPerClus * (root_cluster - 2)) * sector_size;

            unsigned int num_entries = bytes_per_cluster / sizeof(DirEntry);

            for (unsigned int i = 0; i < num_entries; i++)
            {
                DirEntry *dir_entry = (DirEntry *)(addr + root_entry + i * sizeof(DirEntry));
                if (dir_entry->DIR_Name[0] == 0x00)
                {
                    break;
                }
                else if (dir_entry->DIR_Name[0] == 0xe5)
                {
                    continue;
                }
                else if (dir_entry->DIR_Attr == 0x10)
                {
                    total_entries++;
                    char dir_name[12];
                    int index = 0;
                    for (int i = 0; i < 11; i++)
                    {
                        if (dir_entry->DIR_Name[i] != ' ')
                        {
                            dir_name[index++] = dir_entry->DIR_Name[i];
                        }
                    }
                    dir_name[index] = '\0';
                    printf("%s/ ", dir_name);
                    printf("(starting cluster = %d)\n", dir_entry->DIR_FstClusLO);
                }
                else if (dir_entry->DIR_Attr & 0x20)
                {
                    total_entries++;
                    int file_size = dir_entry->DIR_FileSize;
                    char file_name[9];
                    int index1 = 0;
                    for (int i = 0; i < 8; i++)
                    {
                        if (dir_entry->DIR_Name[i] != ' ')
                        {
                            file_name[index1++] = dir_entry->DIR_Name[i];
                        }
                    }
                    file_name[index1] = '\0';
                    printf("%s", file_name);
                    if (dir_entry->DIR_Name[8] != ' ')
                    {
                        char ext[8];
                        int index2 = 0;
                        for (int i = 8; i < 11; i++)
                        {
                            if (dir_entry->DIR_Name[i] != ' ')
                            {
                                ext[index2++] = dir_entry->DIR_Name[i];
                            }
                        }
                        ext[index2] = '\0';
                        printf(".%s", ext);
                    }
                    if (file_size == 0)
                    {
                        printf(" (size = %d)\n", file_size);
                    }
                    else
                    {
                        printf(" (size = %d, starting cluster = %d)\n", dir_entry->DIR_FileSize, dir_entry->DIR_FstClusLO);
                    }
                }
            }
            root_cluster = fat_entry(addr, entry, root_cluster);
        }
        printf("Total number of entries = %d\n", total_entries);
    }

    return 0;
}
