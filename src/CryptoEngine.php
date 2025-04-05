<?php
namespace ChiwiCrypt;

use Exception;
class CryptoEngine
{
  private $keyManager;

  public function __construct(KeyManager $keyManager)
  {
    $this->keyManager = $keyManager;
  }

  /**
   * Genera un nuevo par de claves para un usuario
   */
  public function generateUserKeys($userId, $passphrase = null)
  {
    try {
      $config = [
        "config" => $_ENV["OPENSSL_DIR"],
        "digest_alg" => "sha512",
        "private_key_bits" => 4096,
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
      ];
      $keyPair = openssl_pkey_new($config);
      if (!$keyPair) {
        throw new Exception("No se pudo generar la clave privada");
      }
      // Extraer clave privada (opcionalmente cifrada con passphrase)
      openssl_pkey_export($keyPair, $privateKey, $passphrase, $config);
      // Extraer clave pública
      $keyDetails = openssl_pkey_get_details($keyPair);
      $publicKey = $keyDetails['key'];
      // Almacenar las claves
      $this->keyManager->storeKeys($userId, $publicKey, $privateKey);
      return [
        'user_id' => $userId,
        'public_key' => $publicKey,
        'private_key_stored' => true
      ];
    } catch (Exception $e) {
      throw new Exception($e->getMessage());
    }
  }

  /**
   * Cifra un mensaje para un destinatario específico
   */
  public function encryptMessage($senderId, $recipientId, $message)
  {
    $recipientPublicKey = $this->keyManager->getPublicKey($recipientId);

    if (!$recipientPublicKey) {
      throw new Exception("Clave pública del destinatario no disponible");
    }

    $chunks = str_split($message, 200); // RSA tiene límite de tamaño
    $encrypted = '';

    foreach ($chunks as $chunk) {
      openssl_public_encrypt($chunk, $encryptedChunk, $recipientPublicKey);
      $encrypted .= $encryptedChunk;
    }

    return base64_encode($encrypted);
  }

  /**
   * Descifra un mensaje recibido
   */
  public function decryptMessage($userId, $encryptedMessage, $passphrase = null)
  {
    try {
      $privateKey = $this->keyManager->getPrivateKey($userId, $passphrase);
      $data = base64_decode($encryptedMessage);
      $chunkSize = 512; // Para RSA 4096 bits
      $decrypted = '';
      
      foreach (str_split($data, $chunkSize) as $chunk) {
        if (!@openssl_private_decrypt($chunk, $decryptedChunk, $privateKey)) {
          throw new Exception("Error al desencriptar el mensaje: la clave no es válida");
        }
        $decrypted .= $decryptedChunk;
      }
      return $decrypted;
    } catch (Exception $e) {
      throw new Exception($e->getMessage());
    }
  }

  /**
   * Firma un mensaje
   */
  public function signMessage($userId, $message, $passphrase = null)
  {
    $privateKey = $this->keyManager->getPrivateKey($userId, $passphrase);
    openssl_sign($message, $signature, $privateKey, OPENSSL_ALGO_SHA512);
    return base64_encode($signature);
  }

  /**
   * Verifica una firma
   */
  public function verifySignature($senderId, $message, $signature)
  {
    $publicKey = $this->keyManager->getPublicKey($senderId);
    $sig = base64_decode($signature);
    return openssl_verify($message, $sig, $publicKey, OPENSSL_ALGO_SHA512) === 1;
  }
}