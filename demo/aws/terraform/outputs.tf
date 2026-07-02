output "public_ip" {
  description = "Public IP of the demo host."
  value       = aws_instance.demo.public_ip
}

output "ssh_command" {
  description = "Convenience SSH command (point -i at your key)."
  value       = "ssh -i <your-key.pem> ubuntu@${aws_instance.demo.public_ip}"
}

output "region" {
  value = var.region
}
