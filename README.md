# Multi-Agent Network Intrusion Detection and Automated Response System

[English](#english) | [Türkçe](#türkçe)

---

## English

A multi-agent network intrusion detection system (IDS) that detects attacks in real time and responds automatically by blocking the attacker's IP. The system combines two machine learning models (Random Forest and Isolation Forest) with behavioral rules in a three-layer detection architecture, coordinated by four cooperating agents.

> **Course:** Computer and Network Security
> **Author:** Batuhan Çuvaş
> **Advisor:** Enis Karaarslan

### Overview

The system captures live network traffic, extracts flow features, evaluates them through three detection layers, and takes automated action based on a three-level risk score:

- **LOW** → log only
- **MEDIUM** → warn and monitor
- **HIGH** → block the IP via `iptables`

### Architecture

**Four cooperating agents:**

1. **Monitor** — captures live traffic with scapy and extracts 15 flow features
2. **Analysis** — runs RF + IF models and behavioral rules, produces a weighted-voting risk score
3. **Decision** — selects an action based on the risk level
4. **Response** — applies the action (IP blocking) and measures TTD/TTR

A **feedback loop** closes the cycle: after a block, the Monitor agent verifies that traffic has stopped and reports success back to the Analysis agent.

**Three detection layers:**

1. **Signature (Random Forest)** — supervised, detects known attacks
2. **Anomaly (Isolation Forest)** — unsupervised, flags deviation from normal traffic
3. **Behavioral rules** — directly recognize attack patterns (port scan, SSH brute-force, low-and-slow)

### Models

Both models were trained on the **CICIDS2017** dataset (~2.83M labeled network flows). Instead of all 78 features, **15 live-extractable features** were selected to keep training and live traffic aligned.

| Model | Accuracy | Precision | Recall | F1-Score | FPR |
|-------|----------|-----------|--------|----------|-----|
| Random Forest | 0.9969 | 0.9919 | 0.9923 | 0.9921 | 0.0020 |
| Isolation Forest | 0.8283 | 0.6194 | 0.3312 | 0.4317 | 0.0499 |

The two models are combined with **weighted voting** (0.7 × RF + 0.3 × IF), producing the three-level risk score.

### Detection Scenarios

| Scenario | Attack | Detection | Action |
|----------|--------|-----------|--------|
| Port Scan | `nmap -sS -p 1-1000` | 10+ distinct ports | HIGH → block |
| SSH Brute-Force | `hydra` on port 22 | port 22 traffic + auth.log failed logins | HIGH → block |
| Low-and-Slow | few ports, repeated access | 2–9 ports, repeated | MEDIUM → warn |

### Project Structure

```
01_explore.py        Explore the dataset (merge CSVs, inspect classes)
02_prepare.py        Clean data and select 15 features
03_train_rf.py       Train Random Forest
04_train_if.py       Train Isolation Forest
05_voting.py         Weighted voting and comparison
agents_common.py     Shared message format and logging
agent_monitor.py     Monitor agent (test-data integration)
agent_analysis.py    Analysis agent (RF + IF + behavioral rules)
agent_response.py    Decision and Response agents (+ TTD/TTR)
agent_logwatch.py    Log-watch agent (auth.log)
live_monitor.py      Live capture with scapy + full pipeline
run_system.py        Orchestrator (4 agents + feedback loop)
```

### Setup

**Environment:** Windows host for training; VirtualBox VMs for the live demo (Ubuntu target, Kali attacker) on a Host-Only network.

```bash
# Install dependencies
pip install pandas numpy scikit-learn scapy joblib

# 1. Prepare data and train models (run in order)
python 02_prepare.py
python 03_train_rf.py
python 04_train_if.py
python 05_voting.py

# 2. Run live monitoring on the target machine (Ubuntu, needs root)
sudo venv/bin/python live_monitor.py
```

### Metrics

- **TTD (Time to Detect)** — from attack-behavior start to detection
- **TTR (Time to Respond)** — from detection to IP blocking

Detection happens in seconds; response in milliseconds.

### Limitations & Findings

In the live environment, the ML models often classified attacks as benign, while the **behavioral rules** were what actually caught the attacks. The cause is a **model-data mismatch**: CICIDS2017 was generated with CICFlowMeter, whose feature scale differs from the scapy-based features used live. This finding demonstrates why a layered hybrid architecture is essential — when one layer underperforms, another compensates.

### Future Work

- Live CICFlowMeter integration to resolve the model-data mismatch
- Honeypot redirection (deception) for suspicious IPs
- Immutable audit logging
- Behavior-based detection independent of source IP

### Note on AI Assistance

Generative AI was used as a tool during development (coding assistance, debugging, and documentation), in line with the course guidelines. The project design, decisions, and understanding are the author's own.

---

## Türkçe

Ağ saldırılarını gerçek zamanlı tespit eden ve saldırganın IP'sini otomatik olarak bloklayarak müdahale eden çok-ajanlı bir saldırı tespit sistemi (IDS). Sistem, iki makine öğrenmesi modelini (Random Forest ve Isolation Forest) davranış kurallarıyla birlikte üç katmanlı bir tespit mimarisinde kullanır ve dört iş birliği yapan ajan tarafından yönetilir.

> **Ders:** Computer and Network Security
> **Hazırlayan:** Batuhan Çuvaş
> **Danışman:** Enis Karaarslan

### Genel Bakış

Sistem canlı ağ trafiğini yakalar, akış özelliklerini çıkarır, bunları üç tespit katmanından geçirir ve üç seviyeli bir risk skoruna göre otomatik aksiyon alır:

- **DÜŞÜK** → sadece logla
- **ORTA** → uyar ve izle
- **YÜKSEK** → `iptables` ile IP'yi blokla

### Mimari

**Dört iş birliği yapan ajan:**

1. **İzleme (Monitor)** — scapy ile canlı trafiği yakalar ve 15 akış özelliğini çıkarır
2. **Analiz (Analysis)** — RF + IF modellerini ve davranış kurallarını çalıştırır, ağırlıklı oylamayla risk skoru üretir
3. **Karar (Decision)** — risk seviyesine göre aksiyon seçer
4. **Müdahale (Response)** — aksiyonu uygular (IP bloklama) ve TTD/TTR ölçer

Bir **feedback loop** döngüyü kapatır: bloklamadan sonra İzleme ajanı trafiğin kesildiğini doğrular ve Analiz ajanına başarı bilgisini geri gönderir.

**Üç tespit katmanı:**

1. **İmza (Random Forest)** — denetimli, bilinen saldırıları tespit eder
2. **Anomali (Isolation Forest)** — denetimsiz, normalden sapan trafiği işaretler
3. **Davranış kuralları** — saldırı desenlerini doğrudan tanır (port tarama, SSH brute-force, low-and-slow)

### Modeller

Her iki model de **CICIDS2017** veri setiyle (~2.83M etiketli ağ akışı) eğitildi. 78 özelliğin tamamı yerine, eğitim ve canlı trafiği uyumlu tutmak için **canlı çıkarılabilen 15 özellik** seçildi.

| Model | Accuracy | Precision | Recall | F1-Score | FPR |
|-------|----------|-----------|--------|----------|-----|
| Random Forest | 0.9969 | 0.9919 | 0.9923 | 0.9921 | 0.0020 |
| Isolation Forest | 0.8283 | 0.6194 | 0.3312 | 0.4317 | 0.0499 |

İki model **ağırlıklı oylama** (0.7 × RF + 0.3 × IF) ile birleştirilir ve üç seviyeli risk skoru üretilir.

### Tespit Senaryoları

| Senaryo | Saldırı | Tespit | Aksiyon |
|---------|---------|--------|---------|
| Port Tarama | `nmap -sS -p 1-1000` | 10+ farklı port | YÜKSEK → blok |
| SSH Brute-Force | port 22'ye `hydra` | port 22 trafiği + auth.log başarısız girişler | YÜKSEK → blok |
| Low-and-Slow | az porta tekrarlı erişim | 2–9 port, tekrarlı | ORTA → uyarı |

### Proje Yapısı

```
01_explore.py        Veri setini tanıma (CSV birleştirme, sınıf inceleme)
02_prepare.py        Veriyi temizleme ve 15 özellik seçimi
03_train_rf.py       Random Forest eğitimi
04_train_if.py       Isolation Forest eğitimi
05_voting.py         Ağırlıklı oylama ve karşılaştırma
agents_common.py     Ortak mesaj formatı ve loglama
agent_monitor.py     İzleme ajanı (test verisi entegrasyonu)
agent_analysis.py    Analiz ajanı (RF + IF + davranış kuralları)
agent_response.py    Karar ve Müdahale ajanları (+ TTD/TTR)
agent_logwatch.py    Log izleme ajanı (auth.log)
live_monitor.py      scapy ile canlı yakalama + tam pipeline
run_system.py        Orkestratör (4 ajan + feedback loop)
```

### Kurulum

**Ortam:** Eğitim için Windows; canlı demo için VirtualBox sanal makineleri (Ubuntu hedef, Kali saldırgan) Host-Only ağında.

```bash
# Bağımlılıkları kur
pip install pandas numpy scikit-learn scapy joblib

# 1. Veriyi hazırla ve modelleri eğit (sırayla)
python 02_prepare.py
python 03_train_rf.py
python 04_train_if.py
python 05_voting.py

# 2. Hedef makinede canlı izlemeyi başlat (Ubuntu, root gerekli)
sudo venv/bin/python live_monitor.py
```

### Metrikler

- **TTD (Time to Detect)** — saldırı davranışının başlangıcından tespite kadar geçen süre
- **TTR (Time to Respond)** — tespitten IP bloklamaya kadar geçen süre

Tespit saniyeler, müdahale milisaniyeler içinde gerçekleşir.

### Sınırlamalar ve Bulgular

Canlı ortamda makine öğrenmesi modelleri saldırıları çoğunlukla normal olarak sınıflandırdı; saldırıları asıl yakalayan **davranış kuralları** oldu. Sebep bir **model-veri uyuşmazlığıdır (model-data mismatch)**: CICIDS2017 verisi, canlıda kullanılan scapy özelliklerinden farklı ölçekte olan CICFlowMeter ile üretilmiştir. Bu bulgu, katmanlı hibrit mimarinin neden gerekli olduğunu gösterir — bir katman yetersiz kaldığında diğeri devreye girer.

### Gelecek Çalışmalar

- Model-veri uyuşmazlığını çözmek için canlı CICFlowMeter entegrasyonu
- Şüpheli IP'ler için honeypot yönlendirme (deception)
- Değiştirilemez log kaydı
- Kaynak IP'den bağımsız, davranış bazlı tespit

### Yapay Zeka Kullanımı Hakkında

Geliştirme sürecinde, ders kurallarına uygun olarak, üretken yapay zekadan bir araç olarak yararlanılmıştır (kod yazımı, hata ayıklama ve dokümantasyon). Projenin tasarımı, kararları ve anlaşılması yazara aittir.
