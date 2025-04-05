<?php
namespace ChiwiCrypt;
class KeyManager
{
  private $keysDir;
  private $encryptionKey;

  public function __construct($keysDir, $encryptionKey = null)
  {
    $this->keysDir = rtrim($keysDir, '/') . '/';
    if (!file_exists($this->keysDir)) {
      mkdir($this->keysDir, 0700, true);
    }

    $this->encryptionKey = $encryptionKey ?: $this->generateEncryptionKey();
  }

  public function storeKeys($userId, $publicKey, $privateKey)
  {
    try {
      if ($this->keyExists($userId)) {
        throw new \Exception("Ya existe la clave de este usuario");
      }
      // Almacenar clave pública
      file_put_contents($this->keysDir . "{$userId}_public.pem", $publicKey);
      chmod($this->keysDir . "{$userId}_public.pem", 0644);
      // Cifrar y almacenar clave privada
      $encryptedPrivate = $this->encryptPrivateKey($privateKey);
      file_put_contents($this->keysDir . "{$userId}_private.enc", $encryptedPrivate);
      chmod($this->keysDir . "{$userId}_private.enc", 0600);

    } catch (\Exception $e) {
      throw new \Exception($e->getMessage());

    }
  }

  public function getPublicKey($userId)
  {
    $file = $this->keysDir . "{$userId}_public.pem";
    return file_exists($file) ? openssl_pkey_get_public(file_get_contents($file)) : null;
  }

  public function getPrivateKey($userId, $passphrase = null)
  {
    $file = $this->keysDir . "{$userId}_private.enc";

    if (!file_exists($file)) {
      return null;
    }

    $encrypted = file_get_contents($file);
    $privateKey = $this->decryptPrivateKey($encrypted, $passphrase);
    return $privateKey;
  }

  private function encryptPrivateKey($privateKey, $passphrase = null)
  {
    if ($passphrase) {
      return $privateKey; // Ya está cifrada por openssl_pkey_export
    }

    // Cifrado adicional con clave maestra
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt(
      $privateKey,
      'aes-256-cbc',
      $this->encryptionKey,
      OPENSSL_RAW_DATA,
      $iv
    );

    return base64_encode($iv . $encrypted);
  }

  private function decryptPrivateKey($encrypted, $passphrase = null)
  {
    if ($passphrase) {
      return $encrypted; // Se descifrará con la passphrase
    }

    $data = base64_decode($encrypted);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt(
      $encrypted,
      'aes-256-cbc',
      $this->encryptionKey,
      OPENSSL_RAW_DATA,
      $iv
    );
  }

  private function generateEncryptionKey()
  {
    return hash('sha256', uniqid('', true) . bin2hex(random_bytes(16)));
  }

  private function keyExists($userId)
  {
    $files = scandir($this->keysDir);
    return in_array($userId . "_public.pem", $files);
  }
}