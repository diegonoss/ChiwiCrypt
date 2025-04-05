<?php
echo '<h2>Información de Entorno OpenSSL</h2>';
echo '<pre>';

// 1. Verificar la ruta del archivo de configuración
echo "Ruta actual de openssl.cnf:\n";
echo "Definida en \$_SERVER['OPENSSL_CONF']: " . ($_SERVER['OPENSSL_CONF'] ?? 'NO DEFINIDA') . "\n";
echo "Definida en getenv('OPENSSL_CONF'): " . (getenv('OPENSSL_CONF') ?: 'NO DEFINIDA') . "\n";

// 2. Verificar si PHP puede encontrar el archivo
$defaultPath = $_SERVER['OPENSSL_CONF'];
echo "\nEl archivo existe en la ruta por defecto? " . (file_exists($defaultPath) ? 'SÍ' : 'NO') . "\n";

// 3. Probar la generación de claves
echo "\nProbando generación de clave...\n";
$testConfig = [
    "config" => $defaultPath,
    "digest_alg" => "sha256",
    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
];

$key = openssl_pkey_new($testConfig);
if ($key) {
    echo "✅ Generación de clave exitosa\n";
    openssl_pkey_free($key);
} else {
    echo "❌ Error al generar clave: " . openssl_error_string() . "\n";
}

echo '</pre>';