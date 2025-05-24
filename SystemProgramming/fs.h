#ifndef FS_H
#define FS_H

#include <time.h> 

// Disk ve blok boyutları
#define BLOCK_SIZE 512       // Her blok 512 byte
#define NUM_BLOCKS 2048      // Toplam 2048 blok (512 * 2048 = 1MB)

// Dosya sistemi limitleri
#define MAX_FILES 32         // Maksimum dosya sayısı
#define FILENAME_LEN 32      // Dosya adı maksimum uzunluğu 

// Meta veri alanı boyutu (sabit 4KB)
#define METADATA_AREA_SIZE 4096 // İlk 4KB meta veri alanı 
#define METADATA_BLOCKS (METADATA_AREA_SIZE / BLOCK_SIZE) // Meta veri alanı-blok 

// Dosya girişi yapısı
typedef struct {
    char filename[FILENAME_LEN]; // Dosya adı
    int size;                    // Dosya boyutu (byte)
    int start_block;             // Dosyanın başladığı blok numarası
    int is_used;                 // Bu girişin kullanılıp kullanılmadığı (1:kullanılıyor, 0:boş)
    time_t created_at;           // Oluşturulma tarihi
    time_t modified_at;          // Son değiştirilme tarihi
} FileEntry;

// Dosya sistemi meta veri yapısı
typedef struct {
    FileEntry entries[MAX_FILES]; // Dosya girişleri dizisi
} Metadata;

// Hata Kodları
#define FS_SUCCESS 0
#define FS_ERROR -1

// Fonksiyon prototipleri 
int fs_init();
void fs_close();
void fs_log(const char* format, ...);
int fs_format();
int fs_create(const char *filename);
int fs_delete(const char *filename);
int fs_write(const char *filename, const char *data, int size);
int fs_cat(const char *filename);
int fs_ls();
int fs_read(const char *filename, int offset, int size, char *buffer);
int fs_rename(const char* old_name, const char* new_name);
int fs_exists(char* filename);
int fs_size(char* filename);
int fs_append(const char *filename, const char *data, int size);
int fs_truncate(const char *filename, int new_size);
int fs_copy(const char* src_name, const char* dest_name);
int fs_mv(const char* old_path, const char* new_path);
int fs_backup(const char* backup_filename);
int fs_restore(const char* backup_filename);
int fs_diff(const char* filename1, const char* filename2);
void fs_defragment();
void fs_check_integrity();

#endif 