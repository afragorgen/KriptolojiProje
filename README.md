# KriptolojiProje
Kriptoloji dersi proje ödevi

# Çok Katmanlı Kriptografi Paneli ve Ağ Analizi

Bu proje, **klasik**, **manuel (sıfırdan kodlanan)** ve **modern** kriptografik algoritmaları tek bir **Flask tabanlı web uygulaması** altında toplayan bir kriptoloji projesidir.  
Projenin temel amacı, şifreleme algoritmalarının hem **yazılımsal çıktılarının** hem de **ağ katmanındaki (HTTP paketleri)** davranışlarının analiz edilmesidir.

---

## 🎯 Projenin Amacı

- Klasik ve modern kriptografi algoritmalarının çalışma prensiplerini karşılaştırmalı olarak incelemek  
- **S-DES algoritmasını kütüphane kullanmadan manuel olarak kodlamak**  
- AES ve RSA gibi modern algoritmaların ağ üzerinden iletimi sırasında oluşan paket yapılarını analiz etmek  
- **Wireshark** kullanarak şifreli verilerin ağ üzerinde düz metin olarak taşınmadığını göstermek

---

## 🔐 Kullanılan Algoritmalar

### 🔹 Manuel (Sıfırdan Kodlanan)
- **S-DES (Simplified DES)**  
  - 10-bit anahtar  
  - 8-bit blok yapısı  
  - P-Box, S-Box ve round fonksiyonları manuel olarak implemente edilmiştir
- **Hill Cipher**
  - 2x2 matris çarpımı
  - Mod 29 (Türkçe alfabe uyumu)

### 🔹 Modern (Kütüphane Bazlı)
- **AES-128**
  - Simetrik şifreleme
- **RSA-2048**
  - Asimetrik şifreleme
  - Anahtar üretimi ve padding mekanizmaları

---

## 🖥️ Uygulama Mimarisi

- Uygulama **Flask framework’ü** kullanılarak geliştirilmiştir
- Kullanıcı etkileşimi web arayüzü üzerinden sağlanmaktadır
- Algoritmalar:
  - Klasik
  - Manuel
  - Modern
  olmak üzere kategorize edilmiştir
- Kullanıcıdan alınan veriler **HTTP POST** istekleri ile sunucuya iletilmektedir

---

## 🌐 Ağ Analizi (Wireshark)

Proje kapsamında, kullanıcıdan alınan verilerin ağ üzerinden güvenli şekilde iletildiği **Wireshark Network Analyzer** ile analiz edilmiştir.

- HTTP POST paketleri yakalanmıştır
- Gönderilen verilerin:
  - düz metin olarak taşınmadığı
  - `message=...` parametresi altında şifreli biçimde iletildiği
gözlemlenmiştir

---

## ⚙️ Kurulum ve Çalıştırma

### Gerekli Araçlar
- Python 3.10+
- Flask
- Gerekli Python kütüphaneleri

### Kurulum
```bash
git clone https://github.com/afragorgen/KriptolojiProje.git
cd KriptolojiProje
pip install -r requirements.txt
