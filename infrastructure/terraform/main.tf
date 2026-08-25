# =============================================================================
# FalconIDS — AWS Altyapı Tanımı (Terraform)
# =============================================================================
# Bu dosya, FalconIDS'i AWS üzerinde çalıştırmak için gereken tüm
# altyapıyı (ağ, güvenlik, sunucu) tek seferde oluşturur.
#
# Kullanım:
#   cd infrastructure/terraform
#   terraform init
#   terraform plan  -var="key_name=MY_KEY" -var="my_ip=1.2.3.4/32"
#   terraform apply -var="key_name=MY_KEY" -var="my_ip=1.2.3.4/32"
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# 0. PROVIDER
# ─────────────────────────────────────────────────────────────────────────────
terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. AĞ ALTYAPISI
# ─────────────────────────────────────────────────────────────────────────────

# ── 1a. VPC ──────────────────────────────────────────────────────────────────
# FalconIDS'e özel, izole bir sanal ağ oluşturuyoruz.
# DNS desteği aktif — EC2 instance'a public DNS adı atanabilsin.
resource "aws_vpc" "falconids" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "${var.project_name}-vpc"
    Project = var.project_name
  }
}

# ── 1b. Public Subnet ───────────────────────────────────────────────────────
# EC2 instance'ımız burada yaşayacak. "map_public_ip_on_launch" sayesinde
# sunucu otomatik olarak bir public IP alır (SSH ile bağlanmak için gerekli).
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.falconids.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name    = "${var.project_name}-public-subnet"
    Project = var.project_name
  }
}

# ── 1c. Internet Gateway ────────────────────────────────────────────────────
# VPC'nin internete çıkabilmesi için bir Internet Gateway gerekiyor.
# Bu olmadan EC2'ye dışarıdan erişim mümkün olmaz.
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.falconids.id

  tags = {
    Name    = "${var.project_name}-igw"
    Project = var.project_name
  }
}

# ── 1d. Route Table ─────────────────────────────────────────────────────────
# Subnet'ten çıkan tüm trafiği (0.0.0.0/0) Internet Gateway'e yönlendiriyoruz.
# Bu, klasik bir "public subnet" kalıbıdır.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.falconids.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name    = "${var.project_name}-public-rt"
    Project = var.project_name
  }
}

# ── 1e. Route Table ↔ Subnet Bağlantısı ─────────────────────────────────────
# Route table'ı açıkça subnet'e bağlıyoruz; aksi halde VPC'nin
# varsayılan (internete çıkışsız) route table'ı kullanılır.
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. GÜVENLİK GRUBU (Security Group)
# ─────────────────────────────────────────────────────────────────────────────
# FalconIDS'in hem yönetim (SSH) hem de IDS analiz trafiği (HTTP, ICMP)
# alabilmesi için gereken firewall kurallarını tanımlıyoruz.

resource "aws_security_group" "falconids_sg" {
  name        = "${var.project_name}-sg"
  description = "FalconIDS: SSH (yonetici IP), HTTP ve ICMP (dis dunya)"
  vpc_id      = aws_vpc.falconids.id

  # ── Giriş: SSH (Port 22) — Yalnızca sizin IP'nizden ────────────────────
  # Güvenlik açısından SSH tüm dünyaya değil, yalnızca belirttiğiniz
  # IP adresine açılır. "my_ip" değişkenini CIDR formatında verin.
  ingress {
    description = "SSH — yalnizca yonetici IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  # ── Giriş: HTTP (Port 80) — Herkese açık ──────────────────────────────
  # IDS'in gelen HTTP trafiğini yakalayıp analiz edebilmesi için
  # 80 numaralı portu dış dünyaya açıyoruz.
  ingress {
    description = "HTTP — IDS trafik analizi"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # ── Giriş: ICMP (Ping) — Herkese açık ─────────────────────────────────
  # Ping isteklerini yakalamak ve analiz etmek için ICMP trafiğini
  # kabul ediyoruz. protocol = "icmp", -1 = tüm ICMP tipleri.
  ingress {
    description = "ICMP (Ping) — IDS trafik analizi"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # ── Çıkış: Tüm trafik serbest ─────────────────────────────────────────
  # Sunucunun dışarıya erişimi (paket güncellemeleri, git clone vb.)
  # kısıtlanmıyor.
  egress {
    description = "Tum cikis trafigi serbest"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-sg"
    Project = var.project_name
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. EC2 SUNUCUSU
# ─────────────────────────────────────────────────────────────────────────────

# ── 3a. AMI Seçimi (Ubuntu 22.04 LTS — en güncel) ───────────────────────────
# Sabit bir AMI ID'si yerine "data source" kullanıyoruz. Böylece Terraform
# her zaman seçilen bölgedeki en güncel Ubuntu 22.04 LTS AMI'yi bulur.
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical (Ubuntu'nun resmi AWS hesabı)

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ── 3b. EC2 Instance ────────────────────────────────────────────────────────
resource "aws_instance" "falconids" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.falconids_sg.id]

  # ── User Data: Otomatik Kurulum Scripti ────────────────────────────────
  # Sunucu ilk kez başlatıldığında (boot) bu script otomatik çalışır.
  # 1) Sistem paketlerini günceller.
  # 2) FalconIDS'in derlenmesi için gereken araçları kurar:
  #    - g++        : C++ derleyici
  #    - cmake      : Build sistemi
  #    - make       : Derleme otomasyonu
  #    - libpcap-dev: Paket yakalama kütüphanesi (FalconIDS'in kalbi)
  #    - git        : Proje kodunu klonlamak için
  # 3) Projeyi GitHub'dan klonlar ve derler.
  #
  # NOT: user_data yalnızca ilk boot'ta çalışır. Sonraki yeniden
  #      başlatmalarda tekrar çalışmaz.
  user_data = <<-USERDATA
    #!/bin/bash
    set -euo pipefail

    # -- Log dosyası: hata ayıklama için kurulum çıktılarını kaydet --------
    exec > /var/log/falconids-setup.log 2>&1

    echo "=========================================="
    echo " FalconIDS — Otomatik Kurulum Başlıyor"
    echo "=========================================="

    # 1) Sistem güncelleme
    apt-get update -y
    apt-get upgrade -y

    # 2) Derleme bağımlılıkları
    apt-get install -y \
        g++ \
        cmake \
        make \
        libpcap-dev \
        git

    # 3) Proje klonlama ve derleme
    # -------------------------------------------------------------------
    # Aşağıdaki satırdaki REPO_URL'yi kendi GitHub repo adresinizle
    # değiştirin. Repo henüz GitHub'da değilse bu adımı atlayabilir,
    # SSH ile bağlanıp manuel olarak kodu yükleyebilirsiniz.
    # -------------------------------------------------------------------
    REPO_URL="https://github.com/fatihsoyer9008/FalconIDS.git"
    INSTALL_DIR="/opt/falconids"

    if [ -n "$REPO_URL" ]; then
        git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
        cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
        cmake --build build
        echo "[OK] FalconIDS basariyla derlendi: $INSTALL_DIR/build/netfalcon"
    else
        mkdir -p "$INSTALL_DIR"
        echo "[INFO] Repo URL'si henuz ayarlanmadi."
        echo "       Kodu manuel olarak /opt/falconids dizinine yukleyin."
        echo "       Sonra: cd /opt/falconids && cmake -S . -B build && cmake --build build"
    fi

    echo "=========================================="
    echo " FalconIDS — Kurulum Tamamlandi"
    echo "=========================================="
  USERDATA

  # Sunucu silinip yeniden oluşturulduğunda yeni bir public IP atanır.
  # Elastic IP tercih ediliyorsa ayrıca aws_eip kaynağı eklenmelidir.
  associate_public_ip_address = true

  # Root disk: 20 GB (varsayılan 8 GB IDS logları için yetersiz kalabilir)
  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true

    tags = {
      Name    = "${var.project_name}-root-vol"
      Project = var.project_name
    }
  }

  tags = {
    Name    = "${var.project_name}-server"
    Project = var.project_name
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. ÇIKTILAR (Outputs)
# ─────────────────────────────────────────────────────────────────────────────
# "terraform apply" tamamlandığında bu değerler konsola yazdırılır.
# Sunucuya hızlıca bağlanmak için doğrudan kopyala-yapıştır yapabilirsiniz.

output "instance_id" {
  description = "EC2 Instance ID"
  value       = aws_instance.falconids.id
}

output "instance_public_ip" {
  description = "Sunucunun public IP adresi"
  value       = aws_instance.falconids.public_ip
}

output "instance_public_dns" {
  description = "Sunucunun public DNS adresi"
  value       = aws_instance.falconids.public_dns
}

output "ssh_command" {
  description = "Sunucuya SSH ile bağlanmak için hazır komut"
  value       = "ssh -i ~/.ssh/${var.key_name}.pem ubuntu@${aws_instance.falconids.public_ip}"
}

output "vpc_id" {
  description = "Oluşturulan VPC'nin ID'si"
  value       = aws_vpc.falconids.id
}

output "security_group_id" {
  description = "FalconIDS Security Group ID"
  value       = aws_security_group.falconids_sg.id
}
