<?php
namespace ChiwiCrypt\utils;
class Validate
{

  /**
   * The function `validateArray` checks if specified keys are missing or empty in an array and returns
   * an array of missing keys or `true`.
   * 
   * Args:
   *   array (array): The `validateArray` function takes two parameters: an array `array` and an array
   * `keys`. The function checks if the keys specified in the `keys` array exist in the `array` and
   * if their corresponding values are not null or empty strings. If any key is missing or its value
   *   keys (array): The `keys` parameter in the `validateArray` function is an array containing the
   * keys that need to be present in the input array for validation. These keys are used to check if
   * the corresponding values exist in the input array or are not null or empty.
   * 
   * Returns:
   *   The `validateArray` function returns an array of missing fields if any of the keys specified in
   * the `keys` array are missing, null, or empty in the `array`. If no missing fields are found, it
   * returns `true`.
   */
  public static function validateArray(array $array, array $keys): mixed
  {
    $missingFields = [];
    foreach ($keys as $key) {
      if (!array_key_exists($key, $array) || $array[$key] === null || $array[$key] === "") {
        $missingFields[] = $key;
      }
    }

    return $missingFields ?? true;
  }
  /**
   * The function `parseTypeErrorMessage` in PHP parses a raw error message related to type mismatches
   * in function arguments and returns a formatted error message.
   * 
   * Args:
   *   rawMessage (string): Argument #1 () must be of type string, null given...
   * 
   * Returns:
   *   The `parseTypeErrorMessage` function returns a formatted error message indicating that a
   * parameter must be of a specific type, along with the expected type and the actual type that was
   * given. If the raw message matches the expected format, it will return a message like: "El
   * parámetro 'userId' debe ser de tipo string (se recibió null)". If the raw message does not match
   * the expected
   */
  public static function parseTypeErrorMessage(string $rawMessage): string
  {
    // Ejemplo de mensaje crudo: 
    // "Argument #1 ($userId) must be of type string, null given..."

    if (preg_match('/Argument #\d+ \(\$(\w+)\) must be of type (\w+), (.+?) given/', $rawMessage, $matches)) {
      $argName = $matches[1];  // Ej: "userId"
      $expectedType = $matches[2]; // Ej: "string"
      $givenType = $matches[3];   // Ej: "null"

      return sprintf("El parámetro '%s' debe ser de tipo %s (se recibió %s)", $argName, $expectedType, $givenType);
    }
    return "Tipo de parámetro inválido";
  }
}
