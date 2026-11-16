<?php
// admin.php
require_once 'koneksi.php';
require_once 'crypto_helper.php';

// Handling Form Submit
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit'])) {
    $title = $_POST['title'];
    $content = $_POST['content'];

    // Lakukan Enkripsi Hybrid
    $cryptoResult = encryptContent($content);

    $encPayload = $cryptoResult['encrypted_payload'];
    $iv         = $cryptoResult['iv'];
    $encKey     = $cryptoResult['encrypted_key'];
    $privKey    = $cryptoResult['private_key'];

    // Simpan ke database
    $stmt = $conn->prepare("INSERT INTO admin_contents (title, encrypted_payload, iv, encrypted_key, private_key) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $title, $encPayload, $iv, $encKey, $privKey);
    $stmt->execute();
    $stmt->close();

    header("Location: admin.php");
    exit;
}

// Fetch Semua Data Konten
$result = $conn->query("SELECT * FROM admin_contents ORDER BY id DESC");
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <title>Admin Panel - Data Terenkripsi Hybrid</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 30px;
            background: #f4f6f9;
        }

        .card {
            background: #fff;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }

        th,
        td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }

        th {
            background: #343a40;
            color: #fff;
        }

        input[type="text"],
        textarea {
            width: 100%;
            padding: 8px;
            margin: 6px 0 12px;
            box-sizing: border-box;
        }

        button {
            background: #28a745;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
        }

        .code-block {
            font-family: monospace;
            font-size: 11px;
            word-break: break-all;
            color: #d63384;
        }
    </style>
</head>

<body>

    <h2>Dashboard Admin (Sistem Kriptografi Hybrid)</h2>

    <div class="card">
        <h3>Tambah Konten Rahasia Admin</h3>
        <form action="" method="POST">
            <label>Judul Dokumen:</label>
            <input type="text" name="title" required>

            <label>Isi Konten (Plaintext):</label>
            <textarea name="content" rows="4" required></textarea>

            <button type="submit" name="submit">Enkripsi & Simpan Data</button>
        </form>
    </div>

    <div class="card">
        <h3>Data Konten Halaman Admin</h3>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Judul</th>
                    <th>Tampilan Terenkripsi di DB (Simetris + Asimetris)</th>
                    <th>Hasil Dekripsi (Plaintext)</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($row = $result->fetch_assoc()): ?>
                    <?php
                    $decryptedText = decryptContent(
                        $row['encrypted_payload'],
                        $row['iv'],
                        $row['encrypted_key'],
                        $row['private_key']
                    );
                    ?>
                    <tr>
                        <td><?= $row['id'] ?></td>
                        <td><strong><?= htmlspecialchars($row['title']) ?></strong></td>
                        <td>
                            <strong>Encrypted Payload (AES):</strong>
                            <div class="code-block"><?= htmlspecialchars(substr($row['encrypted_payload'], 0, 40)) ?>...
                            </div>
                            <strong>Encrypted Key (RSA):</strong>
                            <div class="code-block"><?= htmlspecialchars(substr($row['encrypted_key'], 0, 40)) ?>...</div>
                        </td>
                        <td style="color: #0d6efd; font-weight: bold; font-size: 16px;">
                            <?= htmlspecialchars($decryptedText) ?>
                        </td>
                    </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>

</body>

</html>