<?php
declare(strict_types=1);

session_set_cookie_params([
    'httponly' => true,
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'samesite' => 'Strict',
]);
session_start();
header('Content-Type: application/json; charset=utf-8');

require __DIR__ . '/config.php';

function responder(array $dados, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($dados, JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    responder(['ok' => false, 'mensagem' => 'Método não permitido.'], 405);
}

$entrada = json_decode(file_get_contents('php://input'), true);
if (!is_array($entrada)) {
    responder(['ok' => false, 'mensagem' => 'Dados inválidos.'], 400);
}

$acao = $entrada['acao'] ?? '';

if ($acao === 'logout') {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $parametros = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $parametros['path'], $parametros['domain'], $parametros['secure'], $parametros['httponly']);
    }
    session_destroy();
    responder(['ok' => true]);
}

$email = strtolower(trim((string) ($entrada['email'] ?? '')));
$senha = (string) ($entrada['senha'] ?? '');

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $senha === '') {
    responder(['ok' => false, 'mensagem' => 'E-mail ou senha inválidos.'], 422);
}

try {
    if ($acao === 'cadastro_admin') {
        $usuarioId = filter_var($_SESSION['usuario_id'] ?? null, FILTER_VALIDATE_INT);
        if (!$usuarioId) {
            responder(['ok' => false, 'mensagem' => 'Faça login como administrador para cadastrar outro administrador.'], 401);
        }

        $verificarAdmin = mysqli_prepare($conexao, 'SELECT tipo FROM clientes WHERE id = ? LIMIT 1');
        mysqli_stmt_bind_param($verificarAdmin, 'i', $usuarioId);
        mysqli_stmt_execute($verificarAdmin);
        $resultadoAdmin = mysqli_stmt_get_result($verificarAdmin);
        $adminAtual = mysqli_fetch_assoc($resultadoAdmin);
        mysqli_stmt_close($verificarAdmin);
        if (!$adminAtual || in_array(strtolower((string) $adminAtual['tipo']), ['cliente', 'inativo'], true)) {
            responder(['ok' => false, 'mensagem' => 'Somente uma conta administrativa ativa pode cadastrar administradores.'], 403);
        }

        $empresa = trim((string) ($entrada['empresa'] ?? 'Ryan_next_tech'));
        $nome = trim((string) ($entrada['nome'] ?? ''));
        if ($empresa === '' || $nome === '' || strlen($senha) < 10) {
            responder(['ok' => false, 'mensagem' => 'Informe empresa, nome e uma senha com pelo menos 10 caracteres.'], 422);
        }

        $verificarEmail = mysqli_prepare($conexao, 'SELECT id FROM clientes WHERE email = ? LIMIT 1');
        mysqli_stmt_bind_param($verificarEmail, 's', $email);
        mysqli_stmt_execute($verificarEmail);
        mysqli_stmt_store_result($verificarEmail);
        if (mysqli_stmt_num_rows($verificarEmail) > 0) {
            mysqli_stmt_close($verificarEmail);
            responder(['ok' => false, 'mensagem' => 'Já existe uma conta com esse e-mail.'], 409);
        }
        mysqli_stmt_close($verificarEmail);

        $senhaHash = password_hash($senha, PASSWORD_DEFAULT);
        $tipo = 'admin';
        $inserirAdmin = mysqli_prepare($conexao, 'INSERT INTO clientes (nome_empresa, nome, email, senha, tipo) VALUES (?, ?, ?, ?, ?)');
        mysqli_stmt_bind_param($inserirAdmin, 'sssss', $empresa, $nome, $email, $senhaHash, $tipo);
        mysqli_stmt_execute($inserirAdmin);
        $novoId = mysqli_insert_id($conexao);
        mysqli_stmt_close($inserirAdmin);

        responder([
            'ok' => true,
            'usuario' => ['id' => $novoId, 'empresa' => $empresa, 'contato' => $nome, 'email' => $email, 'tipo' => $tipo],
            'redirect' => 'admin.ryan.html',
        ], 201);
    }

    if ($acao === 'cadastro') {
        $empresa = trim((string) ($entrada['empresa'] ?? ''));
        $nome = trim((string) ($entrada['nome'] ?? ''));

        if ($empresa === '' || $nome === '') {
            responder(['ok' => false, 'mensagem' => 'Preencha todos os campos.'], 422);
        }

        $verificar = mysqli_prepare($conexao, 'SELECT id FROM clientes WHERE email = ? LIMIT 1');
        mysqli_stmt_bind_param($verificar, 's', $email);
        mysqli_stmt_execute($verificar);
        mysqli_stmt_store_result($verificar);

        if (mysqli_stmt_num_rows($verificar) > 0) {
            responder(['ok' => false, 'mensagem' => 'Já existe uma conta com esse e-mail.'], 409);
        }

        $senhaHash = password_hash($senha, PASSWORD_DEFAULT);
        $tipo = 'cliente';
        $inserir = mysqli_prepare($conexao, 'INSERT INTO clientes (nome_empresa, nome, email, senha, tipo) VALUES (?, ?, ?, ?, ?)');
        mysqli_stmt_bind_param($inserir, 'sssss', $empresa, $nome, $email, $senhaHash, $tipo);
        mysqli_stmt_execute($inserir);

        $usuario = [
            'id' => mysqli_insert_id($conexao),
            'empresa' => $empresa,
            'contato' => $nome,
            'email' => $email,
            'tipo' => $tipo,
            'etapa' => 0,
            'prazo' => null,
        ];
        session_regenerate_id(true);
        $_SESSION['usuario_id'] = $usuario['id'];
        responder([
            'ok' => true,
            'usuario' => $usuario,
            'redirect' => null
        ], 201);
    }

    if ($acao === 'login') {
        $consulta = mysqli_prepare($conexao, 'SELECT id, nome_empresa, nome, email, senha, tipo FROM clientes WHERE email = ? LIMIT 1');
        mysqli_stmt_bind_param($consulta, 's', $email);
        mysqli_stmt_execute($consulta);
        $resultado = mysqli_stmt_get_result($consulta);
        $registro = mysqli_fetch_assoc($resultado);

        if (!$registro || strtolower((string) $registro['tipo']) === 'inativo' || !password_verify($senha, $registro['senha'])) {
            responder(['ok' => false, 'mensagem' => 'E-mail ou senha incorretos.'], 401);
        }

        $usuario = [
            'id' => (int) $registro['id'],
            'empresa' => $registro['nome_empresa'],
            'contato' => $registro['nome'],
            'email' => $registro['email'],
            'tipo' => $registro['tipo'],
            'etapa' => 0,
            'prazo' => null,
        ];
        session_regenerate_id(true);
        $_SESSION['usuario_id'] = $usuario['id'];
        responder([
            'ok' => true,
            'usuario' => $usuario,
            'redirect' => strtolower((string) $usuario['tipo']) === 'cliente' ? null : 'admin.ryan.html'
        ]);
    }

    responder(['ok' => false, 'mensagem' => 'Ação inválida.'], 400);
} catch (Throwable $erro) {
    error_log('Erro de autenticação: ' . $erro->getMessage());
    responder(['ok' => false, 'mensagem' => 'Não foi possível concluir a operação.'], 500);
}
