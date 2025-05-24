#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>   
#include "fs.h"     

#define DISK_NAME "disk.sim"

static int disk_fd = -1;
static Metadata metadata;

// Boş blokların durumunu takip etmek için 
static unsigned char *free_block_bitmap = NULL;
static int free_block_bitmap_size_bytes; 

// Yardımcı fonksiyon prototipleri
static void load_metadata();
static void save_metadata();
static void load_free_block_bitmap();
static void save_free_block_bitmap();
static int find_free_blocks(int num_blocks);
static void mark_blocks_used(int start_block, int num_blocks);
static void mark_blocks_free(int start_block, int num_blocks);
static int is_block_used(int block_num);

// Yardımcı fonksiyon tanımları

// Bitmap'i başlatma/tüm blokları boş olarak işaretleme
static void initialize_free_block_bitmap() {
    free_block_bitmap_size_bytes = (NUM_BLOCKS + 7) / 8;
    free_block_bitmap = (unsigned char*)calloc(free_block_bitmap_size_bytes, 1); 
    if (free_block_bitmap == NULL) {
        perror("Bitmap için bellek ayırma hatası");
        exit(FS_ERROR); 
    }
    for (int i = 0; i < METADATA_BLOCKS; ++i) {
        mark_blocks_used(i, 1);
    }
}

// Bitmap'i diskten yükleme
static void load_free_block_bitmap() {
    if (disk_fd < 0) {
        fprintf(stderr, "Hata: disk_fd başlatılmamış (load_free_block_bitmap).\n");
        return;
    }
    if (free_block_bitmap == NULL) {
        initialize_free_block_bitmap(); 
    }

    off_t bitmap_disk_offset = METADATA_AREA_SIZE;
    lseek(disk_fd, bitmap_disk_offset, SEEK_SET);
    read(disk_fd, free_block_bitmap, free_block_bitmap_size_bytes);
}

// Bitmap'i diske kaydetme
static void save_free_block_bitmap() {
    if (disk_fd < 0) {
        fprintf(stderr, "Hata: disk_fd başlatılmamış (save_free_block_bitmap).\n");
        return;
    }
    if (free_block_bitmap == NULL) {
        fprintf(stderr, "Hata: free_block_bitmap bellekte başlatılmamış (save_free_block_bitmap).\n");
        return;
    }

    off_t bitmap_disk_offset = METADATA_AREA_SIZE;
    lseek(disk_fd, bitmap_disk_offset, SEEK_SET);
    write(disk_fd, free_block_bitmap, free_block_bitmap_size_bytes);
}

// Belirli bir bloğun kullanılıp kullanılmadığını kontrol etme
static int is_block_used(int block_num) {
    if (block_num < 0 || block_num >= NUM_BLOCKS) {
        fprintf(stderr, "Hata: Geçersiz blok numarası (%d) (is_block_used).\n", block_num);
        return 1; 
    }
    int byte_index = block_num / 8;
    int bit_index = block_num % 8;
    return (free_block_bitmap[byte_index] >> bit_index) & 0x01;
}

// Blokları kullanıldı olarak işaretleme
static void mark_blocks_used(int start_block, int num_blocks) {
    for (int i = 0; i < num_blocks; ++i) {
        int block_num = start_block + i;
        if (block_num >= 0 && block_num < NUM_BLOCKS) {
            int byte_index = block_num / 8;
            int bit_index = block_num % 8;
            free_block_bitmap[byte_index] |= (1 << bit_index);
        }
    }
}

// Blokları boş olarak işaretleme
static void mark_blocks_free(int start_block, int num_blocks) {
    for (int i = 0; i < num_blocks; ++i) {
        int block_num = start_block + i;
        if (block_num >= 0 && block_num < NUM_BLOCKS) {
            int byte_index = block_num / 8;
            int bit_index = block_num % 8;
            free_block_bitmap[byte_index] &= ~(1 << bit_index);
        }
    }
}

// Belirli sayıda ardışık boş blok bulma
static int find_free_blocks(int num_blocks) {
    if (num_blocks <= 0) return -1;

    int bitmap_blocks = (free_block_bitmap_size_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
    int search_start_block = METADATA_BLOCKS + bitmap_blocks;

    for (int i = search_start_block; i < NUM_BLOCKS - num_blocks + 1; ++i) {
        int is_free_chunk = 1;
        for (int j = 0; j < num_blocks; ++j) {
            if (is_block_used(i + j)) {
                is_free_chunk = 0;
                break;
            }
        }
        if (is_free_chunk) {
            return i; // Yeterli boş blok bulundu
        }
    }
    return -1; // Yeterli boş blok bulunamadı
}


// Meta veriyi diskten yükleme
static void load_metadata() {
    if (disk_fd < 0) {
        fprintf(stderr, "Hata: disk_fd başlatılmamış (load_metadata).\n");
        return;
    }
    lseek(disk_fd, 0, SEEK_SET);
    read(disk_fd, &metadata, sizeof(Metadata));
}

// Meta veriyi diske kaydetme
static void save_metadata() {
    if (disk_fd < 0) {
        fprintf(stderr, "Hata: disk_fd başlatılmamış (save_metadata).\n");
        return;
    }
    lseek(disk_fd, 0, SEEK_SET);
    write(disk_fd, &metadata, sizeof(Metadata));
}


int fs_init() {
    // Bitmap bellekte henüz yoksa başlat
    if (free_block_bitmap == NULL) {
        initialize_free_block_bitmap();
    }

    disk_fd = open(DISK_NAME, O_RDWR);
    if (disk_fd < 0) {
        printf("Disk bulunamadı. Yeni disk oluşturuluyor...\n");
        disk_fd = open(DISK_NAME, O_CREAT | O_RDWR, 0666);
        if (disk_fd < 0) {
            perror("Disk oluşturulamadı");
            free(free_block_bitmap); // Hata durumunda belleği serbest bırak
            free_block_bitmap = NULL;
            return FS_ERROR;
        }

        // Toplam disk boyutunu ayarlama
        off_t desired_disk_size = (off_t)BLOCK_SIZE * NUM_BLOCKS;
        if (ftruncate(disk_fd, desired_disk_size) != 0) {
            perror("Disk boyutu ayarlanamadı");
            close(disk_fd);
            disk_fd = -1;
            free(free_block_bitmap);
            free_block_bitmap = NULL;
            return FS_ERROR;
        }

        // Meta veriyi sıfırlama ve kaydetme
        memset(&metadata, 0, sizeof(Metadata));
        save_metadata();

        // Bitmap'i sıfırlama ve kaydetme 
        memset(free_block_bitmap, 0, free_block_bitmap_size_bytes);
        for (int i = 0; i < METADATA_BLOCKS; ++i) {
            mark_blocks_used(i, 1);
        }
        save_free_block_bitmap();

    } else {
        // Disk mevcutsa, meta veriyi ve bitmap'i yükleme
        load_metadata();
        load_free_block_bitmap();
    }
    return FS_SUCCESS;
}

void fs_close() {
    if (disk_fd != -1) {
        save_metadata();       
        save_free_block_bitmap(); 
        close(disk_fd);        
        disk_fd = -1;          // disk_fd'yi sıfırlama
    }
    if (free_block_bitmap != NULL) {
        free(free_block_bitmap); // Bellekteki bitmap'i serbest bırakma
        free_block_bitmap = NULL;
    }
}

// Proje dosyasında istenen simülatör komutları

void fs_log(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

int fs_format() {
    if (disk_fd != -1) { // Açık diski kapatma
        close(disk_fd);
        disk_fd = -1;
    }
    disk_fd = open(DISK_NAME, O_CREAT | O_RDWR | O_TRUNC, 0666);
    if (disk_fd < 0) {
        perror("Disk formatlanamadı (open)");
        return -1;
    }

    // Toplam disk boyutunu ayarlama
    off_t desired_disk_size = (off_t)BLOCK_SIZE * NUM_BLOCKS;
    if (ftruncate(disk_fd, desired_disk_size) != 0) {
        perror("Disk formatlanırken boyut ayarlanamadı");
        close(disk_fd);
        disk_fd = -1;
        return -1;
    }

    // Meta veriyi sıfırlama
    memset(&metadata, 0, sizeof(Metadata));
    save_metadata();

    if (free_block_bitmap == NULL) { 
        initialize_free_block_bitmap();
    } else {
        memset(free_block_bitmap, 0, free_block_bitmap_size_bytes);
    }
    for (int i = 0; i < METADATA_BLOCKS; ++i) {
        mark_blocks_used(i, 1);
    }
    save_free_block_bitmap(); 

    printf("Disk başarıyla formatlandı.\n");
    return 0;
}

int fs_create(const char *filename) {
    load_metadata();
    load_free_block_bitmap();

    // Aynı isimde bir dosyanın zaten mevcut olup olmadığını kontrol etme
    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, filename) == 0) {
            printf("Hata: '%s' isminde bir dosya zaten mevcut.\n", filename);
            return -1;
        }
    }

    // Yeni dosya için boş yer bulma
    int entry_index = -1;
    for (int i = 0; i < MAX_FILES; i++) {
        if (!metadata.entries[i].is_used) {
            entry_index = i;
            break;
        }
    }

    if (entry_index == -1) {
        fprintf(stderr, "Hata: Maksimum dosya sayısına ulaşıldı, dosya oluşturulamadı.\n");
        return -2; // Maksimum dosya sayısına ulaşıldıysa
    }

    // Meta veri girişini doldurma
    strncpy(metadata.entries[entry_index].filename, filename, FILENAME_LEN - 1);
    metadata.entries[entry_index].filename[FILENAME_LEN - 1] = '\0'; 
    metadata.entries[entry_index].size = 0;
    metadata.entries[entry_index].start_block = -1; 
    metadata.entries[entry_index].is_used = 1;
    metadata.entries[entry_index].created_at = time(NULL); // Oluşturulma zamanı
    metadata.entries[entry_index].modified_at = time(NULL); // Değiştirilme zamanı

    save_metadata();
    printf("Dosya '%s' oluşturuldu.\n", filename);
    return 0;
}

int fs_delete(const char *filename) {
    load_metadata();
    load_free_block_bitmap();

    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, filename) == 0) {
            // Eğer dosyaya blok tahsis edilmişse boşaltma
            if (metadata.entries[i].start_block != -1) {
                int blocks_to_free = (metadata.entries[i].size + BLOCK_SIZE - 1) / BLOCK_SIZE;
                if (blocks_to_free == 0 && metadata.entries[i].size > 0) blocks_to_free = 1; 

                if (blocks_to_free == 0 && metadata.entries[i].size == 0 && metadata.entries[i].start_block != -1) {

                } else if (blocks_to_free > 0) {
                    mark_blocks_free(metadata.entries[i].start_block, blocks_to_free);
                }
            }
            // Meta veri girişini temizleme
            memset(&metadata.entries[i], 0, sizeof(FileEntry));
            save_metadata();
            save_free_block_bitmap();
            printf("Dosya '%s' silindi.\n", filename);
            return 0;
        }
    }
    printf("Hata: Dosya '%s' bulunamadı.\n", filename);
    return -1;
}

int fs_write(const char *filename, const char *data, int size) {
    load_metadata();
    load_free_block_bitmap();

    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, filename) == 0) {
            int current_blocks_needed = (metadata.entries[i].size + BLOCK_SIZE - 1) / BLOCK_SIZE;
            if (current_blocks_needed == 0 && metadata.entries[i].size > 0) current_blocks_needed = 1;

            int new_blocks_needed = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
            if (new_blocks_needed == 0 && size > 0) new_blocks_needed = 1;

            if (size == 0) { // Eğer yazılacak veri boşsa
                 if (metadata.entries[i].start_block != -1) {
                    mark_blocks_free(metadata.entries[i].start_block, current_blocks_needed);
                    metadata.entries[i].start_block = -1;
                 }
                metadata.entries[i].size = 0;
                metadata.entries[i].modified_at = time(NULL);
                save_metadata();
                save_free_block_bitmap();
                return 0;
            }

            // Yeni blok tahsisi gerekiyorsa veya boyutu değişiyorsa
            if (metadata.entries[i].start_block == -1 || new_blocks_needed != current_blocks_needed) {
                // Eski blokları boşaltma (varsa)
                if (metadata.entries[i].start_block != -1) {
                    mark_blocks_free(metadata.entries[i].start_block, current_blocks_needed);
                }
                
                // Yeni boş bloklar bulma
                int new_start_block = find_free_blocks(new_blocks_needed);
                if (new_start_block == -1) {
                    fprintf(stderr, "Hata: '%s' için yeterli boş disk alanı yok.\n", filename);
                    return -1;
                }
                mark_blocks_used(new_start_block, new_blocks_needed);
                metadata.entries[i].start_block = new_start_block;
            }

            int disk_offset = metadata.entries[i].start_block * BLOCK_SIZE;
            if (lseek(disk_fd, disk_offset, SEEK_SET) < 0) {
                perror("lseek hatası (fs_write)");
                return -1;
            }
            if (write(disk_fd, data, size) != size) {
                perror("Yazma hatası (fs_write)");
                return -1;
            }

            metadata.entries[i].size = size;
            metadata.entries[i].modified_at = time(NULL); // Değiştirilme zamanı
            save_metadata();
            save_free_block_bitmap();
            printf("Dosya '%s' yazıldı, boyut: %d.\n", filename, size);
            return 0;
        }
    }
    printf("Hata: Dosya '%s' bulunamadı.\n", filename);
    return -1;
}

int fs_cat(const char *filename) {
    load_metadata();

    char *buffer = NULL; 
    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, filename) == 0) {
            if (metadata.entries[i].size == 0) {
                printf("Dosya '%s' boş.\n", filename);
                return 0;
            }
            
            if (metadata.entries[i].start_block == -1) {
                 fprintf(stderr, "Hata: Dosya '%s' blok tahsis edilmemiş ancak boyutu > 0.\n", filename);
                 return -1;
            }

            buffer = (char*)malloc(metadata.entries[i].size + 1); 
            if (buffer == NULL) {
                perror("Bellek ayırma hatası (fs_cat)");
                return -1;
            }

            int offset = metadata.entries[i].start_block * BLOCK_SIZE;
            if (lseek(disk_fd, offset, SEEK_SET) < 0) {
                perror("lseek hatası (fs_cat)");
                free(buffer);
                return -1;
            }
            int bytes_read = read(disk_fd, buffer, metadata.entries[i].size);
            if (bytes_read != metadata.entries[i].size) {
                perror("Okuma hatası (fs_cat)");
                free(buffer);
                return -1;
            }
            buffer[bytes_read] = '\0'; 
            printf("%s\n", buffer);
            free(buffer);
            return 0;
        }
    }
    printf("Hata: Dosya '%s' bulunamadı.\n", filename);
    return -1;
}

int fs_ls() {
    load_metadata();
    printf("Dosyalar:\n");
    int found_files = 0;
    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used) {
            char created_time_str[20];
            char modified_time_str[20];
            strftime(created_time_str, sizeof(created_time_str), "%Y-%m-%d %H:%M", localtime(&metadata.entries[i].created_at));
            strftime(modified_time_str, sizeof(modified_time_str), "%Y-%m-%d %H:%M", localtime(&metadata.entries[i].modified_at));

            printf("%-16s %8d bytes  Blok: %-4d Oluş: %s Son Değ: %s\n",
                   metadata.entries[i].filename,
                   metadata.entries[i].size,
                   metadata.entries[i].start_block,
                   created_time_str,
                   modified_time_str);
            found_files = 1;
        }
    }
    if (!found_files) {
        printf("Disk üzerinde dosya bulunmamaktadır.\n");
    }
    return 0;
}

int fs_read(const char *filename, int offset, int size, char *buffer) {
    load_metadata();

    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, filename) == 0) {
            if (metadata.entries[i].start_block == -1) { // Eğer dosya var ama blok tahsis edilmemişse
                buffer[0] = '\0';
                return 0;
            }

            if (offset < 0 || offset >= metadata.entries[i].size) {
                buffer[0] = '\0';
                return 0;
            }
            
            int available_bytes = metadata.entries[i].size - offset;
            int bytes_to_read = (size > available_bytes) ? available_bytes : size;

            int disk_offset = metadata.entries[i].start_block * BLOCK_SIZE + offset;
            if (lseek(disk_fd, disk_offset, SEEK_SET) < 0) {
                perror("lseek hatası (fs_read)");
                buffer[0] = '\0';
                return -1;
            }
            int result = read(disk_fd, buffer, bytes_to_read);
            if (result < 0) {
                perror("Okuma hatası (fs_read)");
                buffer[0] = '\0';
                return -1;
            }
            buffer[result] = '\0'; 
            return result;
        }
    }
    buffer[0] = '\0'; 
    printf("Hata: Dosya '%s' bulunamadı.\n", filename);
    return -1;
}

int fs_rename(const char* old_name, const char* new_name) {
    load_metadata();

    // Yeni ismin zaten mevcut olup olmadığını kontrol etme
    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, new_name) == 0) {
            fprintf(stderr, "Hata: Yeni isim '%s' zaten kullanımda.\n", new_name);
            return -1;
        }
    }

    // Eski dosyayı bulma ve yeniden adlandırma
    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, old_name) == 0) {
            strncpy(metadata.entries[i].filename, new_name, FILENAME_LEN - 1);
            metadata.entries[i].filename[FILENAME_LEN - 1] = '\0';
            metadata.entries[i].modified_at = time(NULL); // Değiştirilme zamanı
            save_metadata();
            printf("Dosya '%s' '%s' olarak yeniden adlandırıldı.\n", old_name, new_name);
            return 0;
        }
    }

    printf("Hata: Dosya '%s' bulunamadı.\n", old_name);
    return -2; // Eski dosya bulunamadı
}

int fs_exists(char* filename) {
    load_metadata();
    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, filename) == 0) {
            return 1;
        }
    }
    return 0;
}

int fs_size(char* filename) {
    load_metadata();
    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, filename) == 0) {
            return metadata.entries[i].size;
        }
    }
    return -1;
}

int fs_append(const char *filename, const char *data, int size) {
    load_metadata();
    load_free_block_bitmap();

    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, filename) == 0) {
            int current_total_size = metadata.entries[i].size;
            int new_total_size = current_total_size + size;

            int current_blocks_needed = (current_total_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
            if (current_blocks_needed == 0 && current_total_size > 0) current_blocks_needed = 1;

            int new_blocks_needed = (new_total_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
            if (new_blocks_needed == 0 && new_total_size > 0) new_blocks_needed = 1;


            if (new_total_size > (NUM_BLOCKS - (METADATA_BLOCKS + (free_block_bitmap_size_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE)) * BLOCK_SIZE ) {
                 fprintf(stderr, "Hata: Diskte yeterli boş alan yok. (fs_append)\n");
                 return -1;
            }
            
            // Eğer boyut değişiyorsa veya henüz blok tahsis edilmemişse
            if (metadata.entries[i].start_block == -1 || new_blocks_needed > current_blocks_needed) {
                // Eski blokları boşaltma (varsa)
                if (metadata.entries[i].start_block != -1) {
                    mark_blocks_free(metadata.entries[i].start_block, current_blocks_needed);
                }

                // Yeni bloklar bulma
                int new_start_block = find_free_blocks(new_blocks_needed);
                if (new_start_block == -1) {
                    fprintf(stderr, "Hata: '%s' için eklemek üzere yeterli boş disk alanı yok.\n", filename);
                    return -1;
                }
                mark_blocks_used(new_start_block, new_blocks_needed);
                metadata.entries[i].start_block = new_start_block;
            }

            int disk_offset = metadata.entries[i].start_block * BLOCK_SIZE + metadata.entries[i].size;
            if (lseek(disk_fd, disk_offset, SEEK_SET) < 0) {
                perror("lseek hatası (fs_append)");
                return -1;
            }
            if (write(disk_fd, data, size) != size) {
                perror("Yazma hatası (fs_append)");
                return -1;
            }
            metadata.entries[i].size = new_total_size;
            metadata.entries[i].modified_at = time(NULL); // Değiştirilme zamanı
            save_metadata();
            save_free_block_bitmap();
            printf("Dosya '%s'a %d byte eklendi. Yeni boyut: %d.\n", filename, size, new_total_size);
            return 0;
        }
    }
    printf("Hata: Dosya '%s' bulunamadı.\n", filename);
    return -1;
}

int fs_truncate(const char *filename, int new_size) {
    load_metadata();
    load_free_block_bitmap();

    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, filename) == 0) {
            if (new_size < 0) {
                fprintf(stderr, "Hata: Yeni boyut negatif olamaz.\n");
                return -1;
            }

            int old_blocks_needed = (metadata.entries[i].size + BLOCK_SIZE - 1) / BLOCK_SIZE;
            if (old_blocks_needed == 0 && metadata.entries[i].size > 0) old_blocks_needed = 1;

            int new_blocks_needed = (new_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
            if (new_blocks_needed == 0 && new_size > 0) new_blocks_needed = 1;


            if (new_size == 0) { // Dosya sıfırlandıysa
                if (metadata.entries[i].start_block != -1) {
                    mark_blocks_free(metadata.entries[i].start_block, old_blocks_needed);
                    metadata.entries[i].start_block = -1;
                }
            } else if (new_blocks_needed < old_blocks_needed) {
                // Blok sayısı azalıyorsa, fazlalığı boşalt
                mark_blocks_free(metadata.entries[i].start_block + new_blocks_needed, old_blocks_needed - new_blocks_needed);
            } else if (new_blocks_needed > old_blocks_needed) {
                // Blok sayısı artıyorsa, yeni bloklar tahsis et
                if (metadata.entries[i].start_block != -1) { // Eski blokları serbest bırak ve yeniden tahsis et
                     mark_blocks_free(metadata.entries[i].start_block, old_blocks_needed);
                }
                int new_start_block = find_free_blocks(new_blocks_needed);
                if (new_start_block == -1) {
                    fprintf(stderr, "Hata: Kesme için yeterli boş disk alanı yok.\n");
                    if (metadata.entries[i].start_block != -1) { 
                         mark_blocks_used(metadata.entries[i].start_block, old_blocks_needed);
                    }
                    return -1;
                }
                mark_blocks_used(new_start_block, new_blocks_needed);
                metadata.entries[i].start_block = new_start_block;
            }

            metadata.entries[i].size = new_size;
            metadata.entries[i].modified_at = time(NULL); // Değiştirilme zamanı
            save_metadata();
            save_free_block_bitmap();
            printf("Dosya '%s' boyutu %d olarak ayarlandı.\n", filename, new_size);
            return 0;
        }
    }
    printf("Hata: Dosya '%s' bulunamadı.\n", filename);
    return -1;
}

int fs_copy(const char* src_name, const char* dest_name) {
    load_metadata();
    load_free_block_bitmap();

    int src_index = -1;
    // Kaynak dosyanın var olup olmadığını kontrol etme
    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, src_name) == 0) {
            src_index = i;
            break;
        }
    }
    if (src_index == -1) {
        fprintf(stderr, "Hata: Kaynak dosya '%s' bulunamadı.\n", src_name);
        return -1;
    }

    // Hedef ismin zaten mevcut olup olmadığını kontrol etme
    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used && strcmp(metadata.entries[i].filename, dest_name) == 0) {
            fprintf(stderr, "Hata: Hedef dosya '%s' zaten mevcut.\n", dest_name);
            return -2;
        }
    }

    // Yeni dosya için boş yer bulma
    int dest_index = -1;
    for (int i = 0; i < MAX_FILES; i++) {
        if (!metadata.entries[i].is_used) {
            dest_index = i;
            break;
        }
    }
    if (dest_index == -1) {
        fprintf(stderr, "Hata: Maksimum dosya sayısına ulaşıldı, kopya oluşturulamadı.\n");
        return -3;
    }

    int blocks_needed = (metadata.entries[src_index].size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (blocks_needed == 0 && metadata.entries[src_index].size > 0) blocks_needed = 1;
    if (metadata.entries[src_index].size == 0) blocks_needed = 0; 

    int new_start_block = -1;
    if (blocks_needed > 0) {
        new_start_block = find_free_blocks(blocks_needed);
        if (new_start_block == -1) {
            fprintf(stderr, "Hata: Kopya için yeterli boş disk alanı bulunamadı.\n");
            return -4;
        }
        mark_blocks_used(new_start_block, blocks_needed);
    }

    // Meta veri alanlarını kopyalama
    strncpy(metadata.entries[dest_index].filename, dest_name, FILENAME_LEN - 1);
    metadata.entries[dest_index].filename[FILENAME_LEN - 1] = '\0';
    metadata.entries[dest_index].size = metadata.entries[src_index].size;
    metadata.entries[dest_index].start_block = new_start_block;
    metadata.entries[dest_index].is_used = 1;
    metadata.entries[dest_index].created_at = time(NULL);
    metadata.entries[dest_index].modified_at = time(NULL);
    
    // Veri bloklarını kopyalama (sadece source size > 0 ise)
    if (metadata.entries[src_index].size > 0) {
        char *buffer = (char*)malloc(metadata.entries[src_index].size);
        if (buffer == NULL) {
            perror("Bellek ayırma hatası (fs_copy)");
            if (new_start_block != -1) mark_blocks_free(new_start_block, blocks_needed); // Hata durumunda blokları boşalt
            return -5;
        }

        if (lseek(disk_fd, metadata.entries[src_index].start_block * BLOCK_SIZE, SEEK_SET) < 0) {
            perror("lseek hatası (fs_copy - kaynak okuma)");
            free(buffer);
            if (new_start_block != -1) mark_blocks_free(new_start_block, blocks_needed);
            return -6;
        }
        if (read(disk_fd, buffer, metadata.entries[src_index].size) != metadata.entries[src_index].size) {
            perror("Okuma hatası (fs_copy - kaynak okuma)");
            free(buffer);
            if (new_start_block != -1) mark_blocks_free(new_start_block, blocks_needed);
            return -7;
        }

        if (lseek(disk_fd, metadata.entries[dest_index].start_block * BLOCK_SIZE, SEEK_SET) < 0) {
            perror("lseek hatası (fs_copy - hedef yazma)");
            free(buffer);
            if (new_start_block != -1) mark_blocks_free(new_start_block, blocks_needed);
            return -8;
        }
        if (write(disk_fd, buffer, metadata.entries[dest_index].size) != metadata.entries[dest_index].size) {
            perror("Yazma hatası (fs_copy - hedef yazma)");
            free(buffer);
            if (new_start_block != -1) mark_blocks_free(new_start_block, blocks_needed);
            return -9;
        }
        free(buffer);
    }
    
    save_metadata();
    save_free_block_bitmap();
    printf("Dosya '%s' '%s' olarak kopyalandı.\n", src_name, dest_name);
    return 0;
}

int fs_mv(const char* old_path, const char* new_path) {
    return fs_rename(old_path, new_path);
}

int fs_backup(const char* backup_filename) {
    int backup_fd = open(backup_filename, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (backup_fd < 0) {
        perror("Yedek dosyası oluşturulamadı");
        return -1;
    }
    
    off_t disk_total_size = (off_t)BLOCK_SIZE * NUM_BLOCKS;

    if (lseek(disk_fd, 0, SEEK_SET) < 0) {
        perror("lseek hatası (fs_backup)");
        close(backup_fd);
        return -1;
    }
    char buffer[4096];
    ssize_t bytes_read;
    off_t current_pos = 0;

    while (current_pos < disk_total_size && 
           (bytes_read = read(disk_fd, buffer, sizeof(buffer))) > 0) {
        if (write(backup_fd, buffer, bytes_read) != bytes_read) {
            perror("Yedek dosyasına yazma hatası");
            close(backup_fd);
            return -1;
        }
        current_pos += bytes_read;
    }
    
    if (bytes_read < 0) {
        perror("Diskten okuma hatası (fs_backup)");
        close(backup_fd);
        return -1;
    }

    close(backup_fd);
    printf("Disk '%s' olarak yedeklendi.\n", backup_filename);
    return 0;
}

int fs_restore(const char* backup_filename) {
    int backup_fd = open(backup_filename, O_RDONLY);
    if (backup_fd < 0) {
        perror("Yedek dosyası açılamadı");
        return -1;
    }

    off_t disk_total_size = (off_t)BLOCK_SIZE * NUM_BLOCKS;

    if (lseek(disk_fd, 0, SEEK_SET) < 0) {
        perror("lseek hatası (fs_restore)");
        close(backup_fd);
        return -1;
    }
    char buffer[4096];
    ssize_t bytes_read;
    off_t current_pos = 0;

    while (current_pos < disk_total_size && 
           (bytes_read = read(backup_fd, buffer, sizeof(buffer))) > 0) {
        if (write(disk_fd, buffer, bytes_read) != bytes_read) {
            perror("Diske geri yükleme hatası");
            close(backup_fd);
            return -1;
        }
        current_pos += bytes_read;
    }

    if (bytes_read < 0) {
        perror("Yedek dosyadan okuma hatası (fs_restore)");
        close(backup_fd);
        return -1;
    }

    close(backup_fd);
    load_metadata(); 
    load_free_block_bitmap();
    printf("Disk '%s' yedekten geri yüklendi.\n", backup_filename);
    return 0;
}

int fs_diff(const char* filename1, const char* filename2) {
    char *buffer1 = NULL, *buffer2 = NULL;
    int size1 = fs_size((char*)filename1);
    int size2 = fs_size((char*)filename2);

    if (size1 < 0 || size2 < 0) {
        fprintf(stderr, "Hata: Dosyalardan biri bulunamadı veya boyutu alınamadı.\n");
        return -1;
    }
    
    if (size1 != size2) {
        printf("Dosyalar farklı: Boyutları uyuşmuyor (%d vs %d).\n", size1, size2);
        return 1;
    }

    if (size1 == 0) {
        printf("Dosyalar aynı: Her ikisi de boş.\n");
        return 0;
    }

    buffer1 = (char*)malloc(size1);
    buffer2 = (char*)malloc(size2);
    if (buffer1 == NULL || buffer2 == NULL) {
        perror("Bellek ayırma hatası (fs_diff)");
        free(buffer1);
        free(buffer2);
        return -1;
    }

    int read1 = fs_read(filename1, 0, size1, buffer1);
    int read2 = fs_read(filename2, 0, size2, buffer2);

    if (read1 != size1 || read2 != size2) {
        fprintf(stderr, "Hata: Dosyalardan okuma sırasında bir sorun oluştu.\n");
        free(buffer1);
        free(buffer2);
        return -1;
    }

    int result = memcmp(buffer1, buffer2, size1) != 0;
    if (result) {
        printf("Dosyalar farklı: İçerikleri uyuşmuyor.\n");
    } else {
        printf("Dosyalar aynı: İçerikleri aynı.\n");
    }
    
    free(buffer1);
    free(buffer2);
    return result;
}

void fs_defragment() {
    load_metadata();
    load_free_block_bitmap();

    int bitmap_blocks = (free_block_bitmap_size_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
    int current_physical_block = METADATA_BLOCKS + bitmap_blocks;
    
    for(int i = METADATA_BLOCKS; i < NUM_BLOCKS; ++i) { // Sadece veri bloklarını boşalt
        mark_blocks_free(i, 1);
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (!metadata.entries[i].is_used) {
            continue;
        }
        if (metadata.entries[i].start_block == -1 && metadata.entries[i].size == 0) { // Boş ve blok tahsis edilmemiş
             continue;
        }

        int file_blocks_needed = (metadata.entries[i].size + BLOCK_SIZE - 1) / BLOCK_SIZE;
        if (file_blocks_needed == 0 && metadata.entries[i].size > 0) file_blocks_needed = 1;

        if (metadata.entries[i].start_block != current_physical_block) {
            char *file_content_buffer = (char*)malloc(metadata.entries[i].size);
            if (file_content_buffer == NULL) {
                perror("Bellek ayırma hatası (fs_defragment - dosya içeriği)");
                return;
            }
            
            // Veri okuma
            if (metadata.entries[i].start_block != -1) { // Eski blok varsa oku
                if (lseek(disk_fd, metadata.entries[i].start_block * BLOCK_SIZE, SEEK_SET) < 0) {
                    perror("lseek hatası (fs_defragment - okuma)");
                    free(file_content_buffer);
                    return;
                }
                if (read(disk_fd, file_content_buffer, metadata.entries[i].size) != metadata.entries[i].size) {
                    perror("Okuma hatası (fs_defragment)");
                    free(file_content_buffer);
                    return;
                }
            } else { // Dosya boş ve hiç bloğu yok
                memset(file_content_buffer, 0, metadata.entries[i].size);
            }


            // Veri yazma (yeni konuma)
            if (lseek(disk_fd, current_physical_block * BLOCK_SIZE, SEEK_SET) < 0) {
                perror("lseek hatası (fs_defragment - yazma)");
                free(file_content_buffer);
                return;
            }
            if (write(disk_fd, file_content_buffer, metadata.entries[i].size) != metadata.entries[i].size) {
                perror("Yazma hatası (fs_defragment)");
                free(file_content_buffer);
                return;
            }
            
            metadata.entries[i].start_block = current_physical_block; // Meta veriyi güncelleme
            free(file_content_buffer);
        }
        // Yeni bloğu kullanıldı olarak işaretleme
        mark_blocks_used(current_physical_block, file_blocks_needed);
        current_physical_block += file_blocks_needed;
    }
    save_metadata();
    save_free_block_bitmap();
    printf("Disk başarıyla birleştirildi.\n");
}


void fs_check_integrity() {
    load_metadata();
    load_free_block_bitmap();

    // Geçici olarak kullanılacak blokları takip eden bir bitmap kopyası
    int *temp_used_blocks = (int*)calloc(NUM_BLOCKS, sizeof(int));
    if (temp_used_blocks == NULL) {
        perror("Bellek ayırma hatası (fs_check_integrity)");
        return;
    }

    int integrity_ok = 1;

    // Meta veri bloklarını kontrol etme ve işaretleme
    for (int i = 0; i < METADATA_BLOCKS; ++i) {
        if (i >= NUM_BLOCKS) {
            printf("Bütünlük sorunu: Meta veri disk sınırlarını aşıyor (blok %d / %d).\n", i, NUM_BLOCKS);
            integrity_ok = 0; break;
        }
        if (!is_block_used(i)) {
            printf("Bütünlük sorunu: Meta veri bloğu %d boş olarak işaretlenmiş.\n", i);
            integrity_ok = 0; break;
        }
        temp_used_blocks[i] = 1; // Geçici olarak işaretleme
    }
    if (!integrity_ok) { free(temp_used_blocks); return; }

    // Bitmap bloklarını kontrol etme ve işaretleme
    int bitmap_start_block = METADATA_AREA_SIZE / BLOCK_SIZE;
    int bitmap_blocks_count = (free_block_bitmap_size_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for (int i = 0; i < bitmap_blocks_count; ++i) {
        int block_num = bitmap_start_block + i;
        if (block_num >= NUM_BLOCKS) {
            printf("Bütünlük sorunu: Bitmap disk sınırlarını aşıyor (blok %d / %d).\n", block_num, NUM_BLOCKS);
            integrity_ok = 0; break;
        }
        if (!is_block_used(block_num)) {
            printf("Bütünlük sorunu: Bitmap bloğu %d boş olarak işaretlenmiş.\n", block_num);
            integrity_ok = 0; break;
        }
        if (temp_used_blocks[block_num]) { // Overlap check
            printf("Bütünlük sorunu: Bitmap bloğu %d meta veriyle çakışıyor.\n", block_num);
            integrity_ok = 0; break;
        }
        temp_used_blocks[block_num] = 1;
    }
    if (!integrity_ok) { free(temp_used_blocks); return; }

    // Dosya girişlerini ve onların kapladığı blokları kontrol etme
    for (int i = 0; i < MAX_FILES; i++) {
        if (metadata.entries[i].is_used) {
            int file_start_block = metadata.entries[i].start_block;
            int file_size = metadata.entries[i].size;
            int file_blocks_needed = (file_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
            if (file_blocks_needed == 0 && file_size > 0) file_blocks_needed = 1;

            if (file_size > 0 && file_start_block == -1) {
                printf("Bütünlük sorunu: Dosya '%s' (giriş %d) boyutu > 0 ancak başlangıç bloğu -1.\n",
                       metadata.entries[i].filename, i);
                integrity_ok = 0; break;
            }
            if (file_size == 0 && file_start_block != -1) {
                printf("Bütünlük sorunu: Dosya '%s' (giriş %d) boyutu 0 ancak başlangıç bloğu atanmış.\n",
                       metadata.entries[i].filename, i);
            }

            if (file_size > 0) { // Sadece boyutu olan dosyalar için blok kontrolü 
                if (file_start_block < (METADATA_BLOCKS + bitmap_blocks_count) ||
                    file_start_block + file_blocks_needed > NUM_BLOCKS) {
                    printf("Bütünlük sorunu: Dosya '%s' (giriş %d) disk sınırları dışında (başlangıç: %d, bloklar: %d).\n",
                           metadata.entries[i].filename, i, file_start_block, file_blocks_needed);
                    integrity_ok = 0; break;
                }

                for (int b = 0; b < file_blocks_needed; b++) {
                    int current_block = file_start_block + b;
                    if (current_block >= NUM_BLOCKS) {
                        printf("Bütünlük sorunu: Dosya '%s' (giriş %d) blok taraması sırasında disk sınırlarını aşıyor (blok %d).\n",
                               metadata.entries[i].filename, i, current_block);
                        integrity_ok = 0; break;
                    }
                    if (temp_used_blocks[current_block]) {
                        printf("Bütünlük sorunu: Çakışan bloklar veya meta veri/bitmap ile çakışma blok %d (dosya: %s, giriş %d).\n",
                               current_block, metadata.entries[i].filename, i);
                        integrity_ok = 0; break;
                    }
                    if (!is_block_used(current_block)) {
                        printf("Bütünlük sorunu: Dosya '%s' (giriş %d) için tahsis edilmesi gereken blok %d bitmap'te boş görünüyor.\n",
                               metadata.entries[i].filename, i, current_block);
                    }
                    temp_used_blocks[current_block] = 1; 
                }
            }
            if (!integrity_ok) break;
        }
    }

    // Bitmap ile temp_used_blocks karşılaştırması, tüm bloklar doğru işaretlenmiş mi?
    if (integrity_ok) {
        for (int i = 0; i < NUM_BLOCKS; ++i) {
            if (is_block_used(i) != temp_used_blocks[i]) {
                printf("Bütünlük sorunu: Blok %d'nin bitmap durumu tutarsız (bitmap: %d, hesaplanan: %d).\n",
                       i, is_block_used(i), temp_used_blocks[i]);
                integrity_ok = 0;
                break;
            }
        }
    }


    if (integrity_ok) {
        printf("Bütünlük sorunu bulunamadı. Disk durumu sağlam.\n");
    } else {
        printf("Disk bütünlük sorunları bulundu.\n");
    }
    free(temp_used_blocks);
}