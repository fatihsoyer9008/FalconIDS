# =============================================================================
# FalconIDS — Terraform Değişkenleri
# =============================================================================
# Bu dosya, altyapının farklı ortamlara kolayca uyarlanabilmesi için
# tüm yapılandırılabilir parametreleri tek bir yerde toplar.
# =============================================================================

# ── Bölge ────────────────────────────────────────────────────────────────────
variable "aws_region" {
  description = "AWS kaynaklarının oluşturulacağı bölge"
  type        = string
  default     = "eu-west-1"
}

# ── Ağ (VPC / Subnet) ────────────────────────────────────────────────────────
variable "vpc_cidr" {
  description = "FalconIDS VPC'si için CIDR bloğu"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Public subnet CIDR bloğu (VPC CIDR'ın alt kümesi)"
  type        = string
  default     = "10.0.1.0/24"
}

variable "availability_zone" {
  description = "Subnet'in oluşturulacağı Availability Zone"
  type        = string
  default     = "eu-west-1a"
}

# ── EC2 ──────────────────────────────────────────────────────────────────────
variable "instance_type" {
  description = "EC2 instance tipi (Free Tier için t2.micro önerilir)"
  type        = string
  default     = "t2.micro"
}

variable "key_name" {
  description = "SSH erişimi için kullanılacak mevcut AWS Key Pair adı"
  type        = string
  # default yok — kullanıcı 'terraform apply' sırasında girmelidir.
}

# ── Güvenlik ─────────────────────────────────────────────────────────────────
variable "my_ip" {
  description = "SSH erişimine izin verilecek IP (CIDR formatında, ör. 203.0.113.42/32)"
  type        = string
  # default yok — kullanıcı kendi IP'sini girmelidir.
  # İpucu: curl -s https://checkip.amazonaws.com
}

# ── Etiketleme ───────────────────────────────────────────────────────────────
variable "project_name" {
  description = "Tüm kaynaklara eklenecek proje etiketi"
  type        = string
  default     = "FalconIDS"
}
