ENV_FILE="/opt/proje/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "PORT=3000" >> "$ENV_FILE"
  echo "DB_HOST=localhost" >> "$ENV_FILE"
  echo "DB_USER=admin" >> "$ENV_FILE"
  echo "DB_PASS=123456" >> "$ENV_FILE"
  echo ".env dosyası oluşturuldu."
else
  echo ".env dosyası zaten var, değiştirilmedi."
fi