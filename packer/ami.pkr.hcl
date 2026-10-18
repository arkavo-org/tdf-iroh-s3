packer {
  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "binary_s3_uri" {
  type        = string
  description = "S3 URI of the gzipped tdf-iroh-s3 binary (e.g. s3://bucket/path/tdf-iroh-s3.gz)"
}

variable "iam_instance_profile" {
  type        = string
  description = "Instance profile for the build instance; it needs s3:GetObject on binary_s3_uri"
}

variable "ami_name_prefix" {
  type    = string
  default = "tdf-iroh-s3"
}

source "amazon-ebs" "al2023" {
  ami_name      = "${var.ami_name_prefix}-{{timestamp}}"
  instance_type = "t4g.medium"
  region        = var.aws_region

  source_ami_filter {
    filters = {
      name                = "al2023-ami-*-arm64"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["amazon"]
  }

  ssh_username = "ec2-user"
  ssh_timeout  = "5m"

  iam_instance_profile = var.iam_instance_profile

  tags = {
    Name    = "${var.ami_name_prefix}"
    Builder = "packer"
  }
}

build {
  sources = ["source.amazon-ebs.al2023"]

  provisioner "shell" {
    inline = [
      "aws s3 cp ${var.binary_s3_uri} /tmp/tdf-iroh-s3.gz",
      "gunzip -f /tmp/tdf-iroh-s3.gz"
    ]
  }

  provisioner "file" {
    source      = "files/tdf-iroh-s3.service"
    destination = "/tmp/tdf-iroh-s3.service"
  }

  provisioner "file" {
    source      = "files/bootstrap.sh"
    destination = "/tmp/bootstrap.sh"
  }

  provisioner "file" {
    source      = "files/cert-sync.sh"
    destination = "/tmp/cert-sync.sh"
  }

  provisioner "file" {
    source      = "files/tdf-iroh-s3-cert-sync.service"
    destination = "/tmp/tdf-iroh-s3-cert-sync.service"
  }

  provisioner "file" {
    source      = "files/tdf-iroh-s3-cert-sync.timer"
    destination = "/tmp/tdf-iroh-s3-cert-sync.timer"
  }

  provisioner "shell" {
    script          = "scripts/setup-user.sh"
    execute_command = "sudo bash '{{.Path}}'"
  }

  provisioner "shell" {
    script          = "scripts/install.sh"
    execute_command = "sudo bash '{{.Path}}'"
  }
}
