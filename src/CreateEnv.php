<?php

$envFilepath = $_SERVER['OPENSSL_CONF'];
echo "Creating $envFilepath";
if (is_file($envFilepath)) {
  $file = new \SplFileObject($envFilepath);
  // Bucle hasta que termine el archivo
  while (false === $file->eof()) {
    // Trim por linea y guardado en el env
    putenv(trim($file->fgets()));
  }
}