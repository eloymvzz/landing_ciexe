<?php
// send-mail.php
declare(strict_types=1);
header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/config.php';

// Permitir solo POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'Método no permitido.']);
    exit;
}

// Pequeña protección: mismo host (evita hotlinking básico)
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin && parse_url($origin, PHP_URL_HOST) !== $_SERVER['HTTP_HOST']) {
    http_response_code(403);
    echo json_encode(['ok' => false, 'error' => 'Origen no permitido.']);
    exit;
}

// Captura y sanea
$name    = trim((string)($_POST['name'] ?? ''));
$email   = trim((string)($_POST['email'] ?? ''));
$message = trim((string)($_POST['message'] ?? ''));

// Honeypot (campo oculto): si viene con datos => bot
$hp = trim((string)($_POST['website'] ?? ''));
if ($hp !== '') {
    // Responder éxito "silencioso" para no dar pistas a bots
    echo json_encode(['ok' => true]);
    exit;
}

// Validaciones
$errors = [];
if ($name === '' || mb_strlen($name) < 2) {
    $errors['name'] = 'Nombre inválido.';
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors['email'] = 'Correo inválido.';
}
if ($message === '' || mb_strlen($message) < 10) {
    $errors['message'] = 'El mensaje debe tener al menos 10 caracteres.';
}

if ($errors) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'errors' => $errors]);
    exit;
}

// Arma el correo
$subject = 'Nuevo mensaje desde el formulario de ' . SITE_NAME;
$bodyLines = [
    "Has recibido un nuevo mensaje desde el sitio " . SITE_NAME . ":",
    "",
    "Nombre:  {$name}",
    "Correo:  {$email}",
    "IP:      " . ($_SERVER['REMOTE_ADDR'] ?? 'N/D'),
    "Fecha:   " . date('Y-m-d H:i:s'),
    "----------------------------------------",
    $message,
];
$body = implode("\n", $bodyLines);

// Guarda una copia local del mensaje para respaldo
$backupDir = __DIR__ . '/mail-log';
if (!is_dir($backupDir)) {
    @mkdir($backupDir, 0755, true);
}
$backupFile = $backupDir . '/' . date('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.txt';
@file_put_contents($backupFile, $body);

// Cabeceras
$headers = [];
$headers[] = 'MIME-Version: 1.0';
$headers[] = 'Content-Type: text/plain; charset=UTF-8';
$headers[] = 'From: ' . SITE_NAME . ' <' . SENDER_ADDRESS . '>';
$headers[] = 'Reply-To: ' . $email;
$headers[] = 'X-Mailer: PHP/' . phpversion();
$headersStr = implode("\r\n", $headers);

// IMPORTANTE: -f define el envelope sender (mejora entregabilidad)
$additionalParams = '-f ' . escapeshellarg(SENDER_ADDRESS);

// Envía
$sent = @mail(TO_EMAIL, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, $headersStr, $additionalParams);

if (!$sent) {
    // Si tu servidor no tiene MTA, considera usar SMTP con un servicio (SendGrid, Mailgun, 365)
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'No se pudo enviar el correo.']);
    exit;
}

echo json_encode(['ok' => true]);
