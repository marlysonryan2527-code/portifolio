<?php
declare(strict_types=1);

ini_set('display_errors', '0');
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
session_set_cookie_params([
	'httponly' => true,
	'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
	'samesite' => 'Strict',
]);
session_start();

require __DIR__ . '/config.php';
$conexao->set_charset('utf8mb4');

function jsonResponse(array $data, int $status = 200): void
{
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
	exit;
}

function h(string $value): string
{
	return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function validDate(mixed $value): bool
{
	if (!is_string($value)) {
		return false;
	}
	$date = DateTime::createFromFormat('!Y-m-d', $value);
	return $date !== false && $date->format('Y-m-d') === $value;
}

function loadState(mysqli $conexao): array
{
	$clientes = [];
	$result = $conexao->query('SELECT id, nome, doc, email, cidade, segmento, ativo FROM rnt_admin_clientes ORDER BY nome');
	while ($row = $result->fetch_assoc()) {
		$row['ativo'] = (bool) $row['ativo'];
		$clientes[] = $row;
	}

	$faturas = [];
	$result = $conexao->query('SELECT id, cliente, servico, descricao AS `desc`, valor, pagto, emissao, venc, status, criadoPor, criadoEm, tocou, aprovadoPor, aprovadoEm, baixadoPor, pagoEm, canceladoPor, motivo FROM rnt_admin_faturas ORDER BY emissao, id');
	while ($row = $result->fetch_assoc()) {
		$row['id'] = (int) $row['id'];
		$row['valor'] = (float) $row['valor'];
		$row['tocou'] = json_decode($row['tocou'], true) ?: [];
		foreach (['aprovadoPor', 'aprovadoEm', 'baixadoPor', 'pagoEm', 'canceladoPor'] as $key) {
			if ($row[$key] === '' || $row[$key] === '1000-01-01') {
				$row[$key] = null;
			}
		}
		$faturas[] = $row;
	}

	return ['clientes' => $clientes, 'invoices' => $faturas];
}

try {
	$conexao->query("CREATE TABLE IF NOT EXISTS rnt_admin_auth (
		id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
		email VARCHAR(190) NOT NULL UNIQUE,
		password_hash VARCHAR(255) NOT NULL,
		criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
	$conexao->query("CREATE TABLE IF NOT EXISTS rnt_admin_clientes (
		id VARCHAR(64) NOT NULL PRIMARY KEY,
		nome VARCHAR(160) NOT NULL,
		doc VARCHAR(32) NOT NULL DEFAULT '',
		email VARCHAR(190) NOT NULL DEFAULT '',
		cidade VARCHAR(100) NOT NULL DEFAULT '',
		segmento VARCHAR(100) NOT NULL DEFAULT '',
		ativo TINYINT(1) NOT NULL DEFAULT 1
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
	$conexao->query("CREATE TABLE IF NOT EXISTS rnt_admin_faturas (
		id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
		cliente VARCHAR(64) NOT NULL,
		servico VARCHAR(160) NOT NULL,
		descricao VARCHAR(255) NOT NULL DEFAULT '',
		valor DECIMAL(12,2) NOT NULL,
		pagto VARCHAR(80) NOT NULL,
		emissao DATE NOT NULL,
		venc DATE NOT NULL,
		status VARCHAR(24) NOT NULL,
		criadoPor VARCHAR(64) NOT NULL DEFAULT '',
		criadoEm DATE NOT NULL,
		tocou TEXT NOT NULL,
		aprovadoPor VARCHAR(64) NOT NULL DEFAULT '',
		aprovadoEm DATE NOT NULL DEFAULT '1000-01-01',
		baixadoPor VARCHAR(64) NOT NULL DEFAULT '',
		pagoEm DATE NOT NULL DEFAULT '1000-01-01',
		canceladoPor VARCHAR(64) NOT NULL DEFAULT '',
		motivo VARCHAR(255) NOT NULL DEFAULT '',
		INDEX idx_rnt_faturas_emissao (emissao),
		INDEX idx_rnt_faturas_status (status),
		INDEX idx_rnt_faturas_cliente (cliente)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
} catch (Throwable $error) {
	error_log('Admin database setup failed: ' . $error->getMessage());
	http_response_code(500);
	exit('Não foi possível preparar o banco de dados do painel.');
}

$authCount = (int) $conexao->query('SELECT COUNT(*) AS total FROM rnt_admin_auth')->fetch_assoc()['total'];
$csrf = $_SESSION['csrf'] ??= bin2hex(random_bytes(32));

if (isset($_GET['logout'])) {
	$_SESSION = [];
	session_destroy();
	header('Location: admin.ryan.php');
	exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_GET['api'])) {
	$postedCsrf = (string) ($_POST['csrf'] ?? '');
	if (!hash_equals($csrf, $postedCsrf)) {
		http_response_code(400);
		exit('Solicitação inválida. Atualize a página e tente novamente.');
	}

	$email = strtolower(trim((string) ($_POST['email'] ?? '')));
	$password = (string) ($_POST['password'] ?? '');
	$mode = (string) ($_POST['mode'] ?? 'login');

	if ($mode === 'setup' && $authCount === 0) {
		if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 12) {
			$feedback = 'Informe um e-mail válido e uma senha com pelo menos 12 caracteres.';
		} else {
			$stmt = $conexao->prepare('INSERT INTO rnt_admin_auth (id, email, password_hash) VALUES (1, ?, ?)');
			$passwordHash = password_hash($password, PASSWORD_DEFAULT);
			$stmt->bind_param('ss', $email, $passwordHash);
			$stmt->execute();
			session_regenerate_id(true);
			$_SESSION['admin_email'] = $email;
			header('Location: admin.ryan.php');
			exit;
		}
	} elseif ($mode === 'login' && $authCount > 0) {
		$stmt = $conexao->prepare('SELECT email, password_hash FROM rnt_admin_auth WHERE id = 1');
		$stmt->execute();
		$admin = $stmt->get_result()->fetch_assoc();
		if ($admin && hash_equals($admin['email'], $email) && password_verify($password, $admin['password_hash'])) {
			session_regenerate_id(true);
			$_SESSION['admin_email'] = $admin['email'];
			header('Location: admin.ryan.php');
			exit;
		}
		$feedback = 'E-mail ou senha incorretos.';
	} else {
		$feedback = 'Não foi possível concluir o acesso.';
	}
}

if (isset($_GET['api'])) {
	if (empty($_SESSION['admin_email'])) {
		jsonResponse(['error' => 'Autenticação necessária.'], 401);
	}

	if ($_SERVER['REQUEST_METHOD'] === 'GET' && $_GET['api'] === 'state') {
		jsonResponse(array_merge(loadState($conexao), ['admin' => $_SESSION['admin_email']]));
	}

	if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_GET['api'] === 'state') {
		if (!hash_equals($csrf, (string) ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''))) {
			jsonResponse(['error' => 'Token de segurança inválido.'], 403);
		}
		$payload = json_decode(file_get_contents('php://input'), true);
		if (!is_array($payload) || !is_array($payload['clientes'] ?? null) || !is_array($payload['invoices'] ?? null)) {
			jsonResponse(['error' => 'Dados inválidos.'], 400);
		}

		$clientes = [];
		foreach ($payload['clientes'] as $cliente) {
			if (!is_array($cliente) || trim((string) ($cliente['id'] ?? '')) === '' || trim((string) ($cliente['nome'] ?? '')) === '') {
				jsonResponse(['error' => 'Cliente inválido.'], 400);
			}
			$clientes[(string) $cliente['id']] = $cliente;
		}

		$statusPermitidos = ['aguardando', 'receber', 'paga', 'cancelada'];
		foreach ($payload['invoices'] as $fatura) {
			if (!is_array($fatura)
				|| (int) ($fatura['id'] ?? 0) < 1
				|| !isset($clientes[(string) ($fatura['cliente'] ?? '')])
				|| !is_numeric($fatura['valor'] ?? null)
				|| (float) $fatura['valor'] <= 0
				|| !validDate($fatura['emissao'] ?? null)
				|| !validDate($fatura['venc'] ?? null)
				|| !in_array($fatura['status'] ?? '', $statusPermitidos, true)) {
				jsonResponse(['error' => 'Fatura inválida.'], 400);
			}
		}

		try {
			$conexao->begin_transaction();
			$conexao->query('DELETE FROM rnt_admin_faturas');
			$conexao->query('DELETE FROM rnt_admin_clientes');

			$clienteStmt = $conexao->prepare('INSERT INTO rnt_admin_clientes (id, nome, doc, email, cidade, segmento, ativo) VALUES (?, ?, ?, ?, ?, ?, ?)');
			foreach ($clientes as $cliente) {
				$id = (string) $cliente['id'];
				$nome = trim((string) $cliente['nome']);
				$doc = (string) ($cliente['doc'] ?? '');
				$email = (string) ($cliente['email'] ?? '');
				$cidade = (string) ($cliente['cidade'] ?? '');
				$segmento = (string) ($cliente['segmento'] ?? '');
				$ativo = !empty($cliente['ativo']) ? 1 : 0;
				$clienteStmt->bind_param('ssssssi', $id, $nome, $doc, $email, $cidade, $segmento, $ativo);
				$clienteStmt->execute();
			}

			$faturaStmt = $conexao->prepare('INSERT INTO rnt_admin_faturas (id, cliente, servico, descricao, valor, pagto, emissao, venc, status, criadoPor, criadoEm, tocou, aprovadoPor, aprovadoEm, baixadoPor, pagoEm, canceladoPor, motivo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
			foreach ($payload['invoices'] as $fatura) {
				$id = (string) (int) $fatura['id'];
				$cliente = (string) $fatura['cliente'];
				$servico = (string) ($fatura['servico'] ?? '');
				$descricao = (string) ($fatura['desc'] ?? '');
				$valor = number_format((float) $fatura['valor'], 2, '.', '');
				$pagto = (string) ($fatura['pagto'] ?? '');
				$emissao = (string) $fatura['emissao'];
				$venc = (string) $fatura['venc'];
				$status = (string) $fatura['status'];
				$criadoPor = (string) ($fatura['criadoPor'] ?? '');
				$criadoEm = validDate($fatura['criadoEm'] ?? null) ? $fatura['criadoEm'] : $emissao;
				$tocou = json_encode($fatura['tocou'] ?? [], JSON_UNESCAPED_UNICODE);
				$aprovadoPor = (string) ($fatura['aprovadoPor'] ?? '');
				$aprovadoEm = validDate($fatura['aprovadoEm'] ?? null) ? $fatura['aprovadoEm'] : '1000-01-01';
				$baixadoPor = (string) ($fatura['baixadoPor'] ?? '');
				$pagoEm = validDate($fatura['pagoEm'] ?? null) ? $fatura['pagoEm'] : '1000-01-01';
				$canceladoPor = (string) ($fatura['canceladoPor'] ?? '');
				$motivo = (string) ($fatura['motivo'] ?? '');
				$faturaStmt->bind_param('ssssssssssssssssss', $id, $cliente, $servico, $descricao, $valor, $pagto, $emissao, $venc, $status, $criadoPor, $criadoEm, $tocou, $aprovadoPor, $aprovadoEm, $baixadoPor, $pagoEm, $canceladoPor, $motivo);
				$faturaStmt->execute();
			}

			$conexao->commit();
			jsonResponse(['ok' => true]);
		} catch (Throwable $error) {
			$conexao->rollback();
			error_log('Admin state save failed: ' . $error->getMessage());
			jsonResponse(['error' => 'Não foi possível salvar os dados.'], 500);
		}
	}

	jsonResponse(['error' => 'Rota não encontrada.'], 404);
}

if (empty($_SESSION['admin_email'])) {
	$isSetup = $authCount === 0;
	$title = $isSetup ? 'Criar acesso administrativo' : 'Acesso administrativo';
	$button = $isSetup ? 'Criar acesso' : 'Entrar';
	$mode = $isSetup ? 'setup' : 'login';
	$passwordLabel = $isSetup ? 'Senha (mínimo 12 caracteres)' : 'Senha';
	$feedback = $feedback ?? '';
	?><!doctype html>
	<html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
	<title><?= h($title) ?></title>
	<style>body{margin:0;background:#080808;color:#fff;font:16px system-ui;display:grid;place-items:center;min-height:100vh}.box{width:min(390px,calc(100% - 40px));padding:28px;border:1px solid #333;background:#111}h1{font-size:24px;margin:0 0 22px}label{display:block;margin:14px 0 6px;color:#bbb}input{box-sizing:border-box;width:100%;padding:12px;background:#080808;color:white;border:1px solid #444}button{margin-top:20px;width:100%;padding:12px;background:#22c55e;border:0;font-weight:700;cursor:pointer}.msg{color:#ff9f9f}</style>
	<main class="box"><h1><?= h($title) ?></h1>
	<?php if ($feedback !== ''): ?><p class="msg" role="alert"><?= h($feedback) ?></p><?php endif; ?>
	<form method="post"><input type="hidden" name="csrf" value="<?= h($csrf) ?>"><input type="hidden" name="mode" value="<?= h($mode) ?>">
	<label for="email">E-mail</label><input id="email" name="email" type="email" autocomplete="username" required>
	<label for="password"><?= h($passwordLabel) ?></label><input id="password" name="password" type="password" autocomplete="<?= $isSetup ? 'new-password' : 'current-password' ?>" required <?= $isSetup ? 'minlength="12"' : '' ?>>
	<button><?= h($button) ?></button></form></main></html><?php
	exit;
}

$html = file_get_contents(__DIR__ . '/admin.ryan.html');
if ($html === false) {
	http_response_code(500);
	exit('Não foi possível carregar o painel.');
}
$bootstrap = '<script>window.ADMIN_API_URL="admin.ryan.php?api=state";window.ADMIN_CSRF=' . json_encode($csrf) . ';</script>';
echo str_replace('</head>', $bootstrap . '</head>', $html);
