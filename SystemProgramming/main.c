#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fs.h"

#define BUFFER_SIZE 1024

void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

int main() {
    char filename[FILENAME_LEN];
    char newname[FILENAME_LEN];
    char data[BUFFER_SIZE];
    char backup_filename[FILENAME_LEN];
    int size, offset;
    int choice;

    // Dosya sistemini başlatma (disk.sim açma veya oluşturma)
    if (fs_init() != 0) {
        printf("Dosya sistemi başlatılamadı.\n");
        return 1;
    }

    while (1) {
        printf("\n=== Menü ===\n");
        printf("1. Dosya oluştur\n");
        printf("2. Dosya sil\n");
        printf("3. Dosyaya veri yaz\n");
        printf("4. Dosyadan veri oku\n");
        printf("5. Dosya üzerine ekleme\n");
        printf("6. Dosyayı yeniden adlandır\n");
        printf("7. Dosyayı kopyala\n");
        printf("8. Dosya boyutunu göster\n");
        printf("9. Dosyaları listele\n");
        printf("10. Disk formatla\n");
        printf("11. Diski yedekle\n");
        printf("12. Yedekten geri yükle\n");
        printf("13. Disk bütünlüğünü kontrol et\n");
        printf("14. Diski birleştir (defragment)\n");
        printf("0. Çıkış\n");
        printf("Seçiminiz: ");

        if (scanf("%d", &choice) != 1) {
            printf("Geçersiz giriş!\n");
            clear_input_buffer();
            continue;
        }
        clear_input_buffer();

        switch (choice) {
            case 1:
                printf("Oluşturulacak dosya adı: ");
                fgets(filename, FILENAME_LEN, stdin);
                filename[strcspn(filename, "\n")] = 0;
                if (fs_create(filename) == 0) {
                    printf("Dosya oluşturuldu: %s\n", filename);
                } else {
                    printf("Dosya oluşturulamadı.\n");
                }
                break;

            case 2:
                printf("Silinecek dosya adı: ");
                fgets(filename, FILENAME_LEN, stdin);
                filename[strcspn(filename, "\n")] = 0;
                if (fs_delete(filename) == 0) {
                    printf("Dosya silindi: %s\n", filename);
                } else {
                    printf("Dosya silinemedi.\n");
                }
                break;

            case 3:
                printf("Yazılacak dosya adı: ");
                fgets(filename, FILENAME_LEN, stdin);
                filename[strcspn(filename, "\n")] = 0;

                printf("Veri: ");
                fgets(data, BLOCK_SIZE, stdin);
                data[strcspn(data, "\n")] = 0;

                fs_write(filename, data, strlen(data));
                printf("Veri yazıldı.\n");
                break;

            case 4:
                printf("Veri okunacak dosya adı: ");
                fgets(filename, FILENAME_LEN, stdin);
                filename[strcspn(filename, "\n")] = 0;
                printf("Başlangıç offset'i: ");
                if (scanf("%d", &offset) != 1) {
                    printf("Geçersiz sayı.\n");
                    clear_input_buffer();
                    break;
                }
                clear_input_buffer();
                printf("Okunacak byte sayısı: ");
                if (scanf("%d", &size) != 1) {
                    printf("Geçersiz sayı.\n");
                    clear_input_buffer();
                    break;
                }
                clear_input_buffer();
                if (size > BUFFER_SIZE - 1) size = BUFFER_SIZE - 1;
                if (fs_read(filename, offset, size, data) >= 0) {
                    data[size] = '\0';
                    printf("Okunan veri: %s\n", data);
                } else {
                    printf("Veri okunamadı.\n");
                }
                break;

            case 5:
                printf("Veri eklenecek dosya adı: ");
                fgets(filename, FILENAME_LEN, stdin);
                filename[strcspn(filename, "\n")] = 0;
                printf("Eklenecek veri (en fazla %d karakter): ", BUFFER_SIZE - 1);
                fgets(data, BUFFER_SIZE, stdin);
                data[strcspn(data, "\n")] = 0;
                size = strlen(data);
                if (fs_append(filename, data, size) == 0) {
                    printf("Veri eklendi.\n");
                } else {
                    printf("Veri eklenemedi.\n");
                }
                break;

            case 6:
                printf("Mevcut dosya adı: ");
                fgets(filename, FILENAME_LEN, stdin);
                filename[strcspn(filename, "\n")] = 0;
                printf("Yeni dosya adı: ");
                fgets(newname, FILENAME_LEN, stdin);
                newname[strcspn(newname, "\n")] = 0;

                int result = fs_rename(filename, newname);
                if (result == 0) {
                    printf("Dosya adı başarıyla değiştirildi.\n");
                } else if (result == -1) {
                    printf("Hata: '%s' adlı bir dosya zaten mevcut.\n", newname);
                } else if (result == -2) {
                    printf("Hata: '%s' adlı dosya bulunamadı.\n", filename);
                }
                break;

            case 7:
                printf("Kaynak dosya adı: ");
                fgets(filename, FILENAME_LEN, stdin);
                filename[strcspn(filename, "\n")] = 0;
                printf("Kopyalanacak yeni dosya adı: ");
                fgets(newname, FILENAME_LEN, stdin);
                newname[strcspn(newname, "\n")] = 0;

                int copy_result = fs_copy(filename, newname);
                if (copy_result == 0) {
                    printf("Dosya başarıyla kopyalandı.\n");
                } else if (copy_result == -1) {
                    printf("Hata: '%s' adlı kaynak dosya bulunamadı.\n", filename);
                } else if (copy_result == -2) {
                    printf("Hata: '%s' adlı bir dosya zaten mevcut.\n", newname);
                } else if (copy_result == -3) {
                    printf("Hata: Yeni dosya için yer yok.\n");
                }
                break;

            case 8:
                printf("Boyutu öğrenilecek dosya adı: ");
                fgets(filename, FILENAME_LEN, stdin);
                filename[strcspn(filename, "\n")] = 0;
                size = fs_size(filename);
                if (size >= 0) {
                    printf("Dosya boyutu: %d byte\n", size);
                } else {
                    printf("Dosya bulunamadı.\n");
                }
                break;

            case 9:
                fs_ls();
                break;

            case 10:
                printf("Disk formatlanacak, devam edilsin mi? (e/h): ");
                char confirm;
                scanf("%c", &confirm);
                clear_input_buffer();
                if (confirm == 'e' || confirm == 'E') {
                    if (fs_format() == 0) {
                        printf("Disk formatlandı.\n");
                    } else {
                        printf("Format başarısız.\n");
                    }
                } else {
                    printf("Format iptal edildi.\n");
                }
                break;

            case 11:
                printf("Yedek dosya adı: ");
                fgets(backup_filename, FILENAME_LEN, stdin);
                backup_filename[strcspn(backup_filename, "\n")] = 0;
                if (fs_backup(backup_filename) == 0) {
                    printf("Yedekleme başarılı.\n");
                } else {
                    printf("Yedekleme başarısız.\n");
                }
                break;

            case 12:
                printf("Geri yüklenecek yedek dosya adı: ");
                fgets(backup_filename, FILENAME_LEN, stdin);
                backup_filename[strcspn(backup_filename, "\n")] = 0;
                if (fs_restore(backup_filename) == 0) {
                    printf("Geri yükleme başarılı.\n");
                } else {
                    printf("Geri yükleme başarısız.\n");
                }
                break;

            case 13:
                fs_check_integrity();
                printf("Disk bütünlüğü kontrol edildi.\n");
                break;

            case 14:
                fs_defragment();
                printf("Disk birleştirme tamamlandı.\n");
                break;

            case 0:
                printf("Çıkış yapılıyor...\n");
                fs_close();  // Disk dosyasını kapatma
                return 0;

            default:
                printf("Geçersiz seçim!\n");
        }
    }

    return 0;
}