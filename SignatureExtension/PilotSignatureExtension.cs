using System;
using System.ComponentModel.Composition;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Forms;
using Ascon.Pilot.SDK;
using Ascon.Pilot.SDK.Menu;

// Разрешаем конфликт имён
using PilotDataObject = Ascon.Pilot.SDK.IDataObject;

namespace PilotSignatureExtension
{
    /// <summary>
    /// Расширение для Pilot-ICE Enterprise
    /// Добавляет пункт "Создать откреплённую подпись" в контекстное меню:
    /// 1. На Storage (диск P:\) — подпись создаётся сразу
    /// 2. В ECM-документе — проверяет монтирование, при необходимости показывает инструкцию
    /// </summary>
    [Export(typeof(IMenu<StorageContext>))]
    [Export(typeof(IMenu<DocumentFilesContext>))]
    public class SignatureExtension : IMenu<StorageContext>, IMenu<DocumentFilesContext>
    {
        // ========== КОНСТАНТЫ ==========
        private const string MENU_ITEM_NAME = "CreateDetachedSignature";

        // ========== ПОЛЯ ==========
        private readonly IObjectsRepository _repository;
        private readonly IObjectModifier _modifier;
        private readonly IFileProvider _fileProvider;
        private readonly string _logFilePath;

        // ========== КОНСТРУКТОР ==========
        [ImportingConstructor]
        public SignatureExtension(
            IObjectsRepository repository,
            IObjectModifier modifier,
            IFileProvider fileProvider)
        {
            _repository = repository;
            _modifier = modifier;
            _fileProvider = fileProvider;

            // Лог в указанную папку
            _logFilePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "ASCON",
                "Pilot-ICE Enterprise",
                "Logs",
                "User_Logs",
                "SignatureExtension.log");

            try { Directory.CreateDirectory(Path.GetDirectoryName(_logFilePath)); } catch { }

            Log("========================================");
            Log("=== Плагин подписи загружен ===");
            Log("=== Поддерживаемые контексты: Storage, DocumentFiles ===");
            Log($"Лог-файл: {_logFilePath}");
            Log("========================================");
        }

        private void Log(string message)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                File.AppendAllText(_logFilePath, timestamp + " - " + message + Environment.NewLine);
            }
            catch { }
        }

        // ========== ДОБАВЛЕНИЕ ПУНКТА В МЕНЮ (STORAGE) ==========
        public void Build(IMenuBuilder builder, StorageContext context)
        {
            try
            {
                // Получаем выбранные объекты через рефлексию
                var selectedObjects = GetSelectedStorageObjects(context);
                if (selectedObjects != null && selectedObjects.Count == 1)
                {
                    var selectedFile = selectedObjects[0];
                    bool isDirectory = GetIsDirectory(selectedFile);
                    if (!isDirectory)
                    {
                        builder.AddItem(MENU_ITEM_NAME, 0)
                               .WithHeader("Создать откреплённую подпись");
                        Log("Пункт меню добавлен (StorageContext)");
                    }
                }
            }
            catch (Exception ex)
            {
                Log("Ошибка в Build (StorageContext): " + ex.Message);
            }
        }

        // ========== ОБРАБОТЧИК КЛИКА (STORAGE) ==========
        public void OnMenuItemClick(string name, StorageContext context)
        {
            if (name != MENU_ITEM_NAME) return;

            Log("========================================");
            Log("=== НАЧАЛО ПОДПИСИ (STORAGE) ===");
            Log("========================================");

            try
            {
                var selectedObjects = GetSelectedStorageObjects(context);
                if (selectedObjects == null || selectedObjects.Count == 0)
                {
                    Log("Ошибка: не выбран файл");
                    MessageBox.Show("Не выбран файл для подписи", "Ошибка",
                                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                var selectedFile = selectedObjects[0];

                // Проверяем, что это файл (не папка)
                bool isDirectory = GetIsDirectory(selectedFile);
                if (isDirectory)
                {
                    Log("Ошибка: выбранный объект является папкой");
                    MessageBox.Show("Выберите файл для подписи", "Ошибка",
                                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                // Получаем путь к файлу
                string filePath = GetFilePath(selectedFile);
                Log($"Путь к файлу: {filePath}");

                if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                {
                    Log($"Ошибка: файл не найден: {filePath}");
                    MessageBox.Show($"Файл не найден:\n{filePath}", "Ошибка",
                                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                // Получаем имя файла
                string fileName = GetFileName(selectedFile);
                Log($"Имя файла: {fileName}");

                // Получаем сертификат
                X509Certificate2 certificate = GetCertificate();
                if (certificate == null) return;

                // Выполняем подпись
                ExecuteSignature(filePath, fileName, certificate);
            }
            catch (Exception ex)
            {
                Log("ОШИБКА: " + ex.Message);
                MessageBox.Show("Ошибка: " + ex.Message, "Ошибка",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // ========== ДОБАВЛЕНИЕ ПУНКТА В МЕНЮ (DOCUMENT FILES) ==========
        public void Build(IMenuBuilder builder, DocumentFilesContext context)
        {
            try
            {
                var selectedFiles = GetSelectedDocumentFiles(context);
                if (selectedFiles != null && selectedFiles.Count == 1)
                {
                    builder.AddItem(MENU_ITEM_NAME, 0)
                           .WithHeader("Создать откреплённую подпись");
                    Log("Пункт меню добавлен (DocumentFilesContext)");
                }
            }
            catch (Exception ex)
            {
                Log("Ошибка в Build (DocumentFilesContext): " + ex.Message);
            }
        }

        // ========== ОБРАБОТЧИК КЛИКА (DOCUMENT FILES) ==========
        public void OnMenuItemClick(string name, DocumentFilesContext context)
        {
            if (name != MENU_ITEM_NAME) return;

            Log("========================================");
            Log("=== НАЧАЛО ПОДПИСИ (DOCUMENT FILES) ===");
            Log("========================================");

            try
            {
                var selectedFiles = GetSelectedDocumentFiles(context);
                if (selectedFiles == null || selectedFiles.Count == 0)
                {
                    Log("Ошибка: не выбран файл");
                    MessageBox.Show("Не выбран файл для подписи", "Ошибка",
                                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                var selectedFile = selectedFiles[0];

                // Получаем путь к файлу
                string filePath = GetFilePath(selectedFile);
                Log($"Путь к файлу: {(string.IsNullOrEmpty(filePath) ? "пусто" : filePath)}");

                // Получаем имя файла
                string fileName = GetFileName(selectedFile);
                Log($"Имя файла: {fileName}");

                // Если путь пустой — папка не смонтирована
                if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                {
                    Log("Папка не смонтирована, показываем инструкцию");

                    MessageBox.Show(
                        "Папка документа не смонтирована на диск Pilot-Enterprise Storage.\n\n" +
                        "Для создания откреплённой подписи файла необходимо, чтобы папка документа была смонтирована.\n\n" +
                        "Нажмите «Показать файлы на диске» правее над файлами и повторите попытку создания подписи непосредственно на диске Pilot-Enterprise Storage.",
                        "Необходимо смонтировать папку",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);

                    Log("Пользователь получил инструкцию");
                    return;
                }

                // Получаем сертификат
                X509Certificate2 certificate = GetCertificate();
                if (certificate == null) return;

                // Путь есть — выполняем подпись
                ExecuteSignature(filePath, fileName, certificate);
            }
            catch (Exception ex)
            {
                Log("ОШИБКА: " + ex.Message);
                MessageBox.Show("Ошибка: " + ex.Message, "Ошибка",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // ========== ПОЛУЧЕНИЕ СЕРТИФИКАТА ==========
        private X509Certificate2 GetCertificate()
        {
            Log("Поиск сертификата...");

            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                var certs = store.Certificates
                    .Find(X509FindType.FindByTimeValid, DateTime.Now, false)
                    .Cast<X509Certificate2>()
                    .Where(c => c.HasPrivateKey)
                    .ToList();

                Log($"Найдено сертификатов: {certs.Count}");

                if (certs.Count == 0)
                {
                    Log("Ошибка: нет действительных сертификатов");
                    MessageBox.Show("Нет действительных сертификатов.\n\n" +
                                    "Убедитесь, что у вас установлен сертификат для электронной подписи.",
                                    "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return null;
                }

                var certificate = certs.First();
                Log($"Сертификат: {certificate.SubjectName.Name}");
                Log($"Действителен до: {certificate.NotAfter:yyyy-MM-dd}");

                return certificate;
            }
        }

        // ========== ОСНОВНАЯ ЛОГИКА ПОДПИСИ ==========
        private void ExecuteSignature(string filePath, string fileName, X509Certificate2 certificate)
        {
            Log($"Начало подписи файла: {filePath}");

            // 1. Проверяем существование файла
            if (!File.Exists(filePath))
            {
                Log($"Ошибка: файл не найден: {filePath}");
                MessageBox.Show($"Файл не найден:\n{filePath}", "Ошибка",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            Log($"Файл существует, размер: {new FileInfo(filePath).Length} байт");

            // 2. Читаем файл
            Log("Чтение файла...");
            byte[] fileContent = File.ReadAllBytes(filePath);
            Log($"Прочитано {fileContent.Length} байт");

            // 3. Создаём подпись
            Log("Создание PKCS#7 откреплённой подписи...");
            byte[] signature = SignContent(fileContent, certificate);
            Log($"Подпись создана, размер: {signature.Length} байт");

            // 4. Формируем имя файла подписи (сокращённое ФИО)
            string shortName = GetShortAuthorName();
            Log($"Автор (сокращённо): {shortName}");

            // Берём полное имя файла с расширением
            string fullFileName = Path.GetFileName(fileName);  // например, "документ.pdf"
            string nameWithoutExt = Path.GetFileNameWithoutExtension(fullFileName);  // "документ"
            string ext = Path.GetExtension(fullFileName);  // ".pdf"
           // Формируем: документ.pdf_ЕреминаДВ.sig
            string sigFileName = fullFileName + "_" + shortName + ".sig";

            string sigFilePath = Path.Combine(Path.GetDirectoryName(filePath), sigFileName);

            Log($"Имя файла подписи: {sigFileName}");
            Log($"Путь к файлу подписи: {sigFilePath}");

            // 5. Сохраняем подпись
            File.WriteAllBytes(sigFilePath, signature);
            Log($"Подпись сохранена, размер: {new FileInfo(sigFilePath).Length} байт");

            Log("========================================");
            Log("=== ПОДПИСЬ УСПЕШНО СОЗДАНА ===");
            Log("========================================");

            // Формируем информацию о сертификате для сообщения пользователю
            string certInfo = $"Сертификат:\n" +
                              $"  Владелец: {certificate.SubjectName.Name}\n" +
                              $"  Отпечаток: {certificate.Thumbprint}\n" +
                              $"  Действителен до: {certificate.NotAfter:dd.MM.yyyy}";

            MessageBox.Show($"Подпись успешно создана!\n\n" +
                            $"Файл: {sigFileName}\n" +
                            $"Папка: {Path.GetDirectoryName(sigFilePath)}\n\n" +
                            $"{certInfo}",
                            "Успех", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // ========== ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ==========

        private System.Collections.Generic.List<object> GetSelectedStorageObjects(StorageContext context)
        {
            var result = new System.Collections.Generic.List<object>();

            var prop = context.GetType().GetProperty("SelectedObjects");
            if (prop != null)
            {
                var value = prop.GetValue(context);
                if (value is System.Collections.IEnumerable enumerable)
                {
                    foreach (var item in enumerable)
                        result.Add(item);
                    Log($"GetSelectedStorageObjects: найдено {result.Count} объектов через SelectedObjects");
                    return result;
                }
            }

            prop = context.GetType().GetProperty("Objects");
            if (prop != null)
            {
                var value = prop.GetValue(context);
                if (value is System.Collections.IEnumerable enumerable)
                {
                    foreach (var item in enumerable)
                        result.Add(item);
                    Log($"GetSelectedStorageObjects: найдено {result.Count} объектов через Objects");
                    return result;
                }
            }

            Log("GetSelectedStorageObjects: не удалось получить выбранные объекты");
            return result;
        }

        private System.Collections.Generic.List<object> GetSelectedDocumentFiles(DocumentFilesContext context)
        {
            var result = new System.Collections.Generic.List<object>();
            var prop = context.GetType().GetProperty("SelectedObjects");
            if (prop != null)
            {
                var value = prop.GetValue(context);
                if (value is System.Collections.IEnumerable enumerable)
                {
                    foreach (var item in enumerable)
                        result.Add(item);
                }
            }
            return result;
        }

        private string GetFilePath(object storageObject)
        {
            var prop = storageObject.GetType().GetProperty("Path");
            if (prop != null)
                return prop.GetValue(storageObject)?.ToString() ?? "";

            var field = storageObject.GetType().GetField("Path",
                System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
            if (field != null)
                return field.GetValue(storageObject)?.ToString() ?? "";

            return "";
        }

        private string GetFileName(object storageObject)
        {
            var dataObjectProp = storageObject.GetType().GetProperty("DataObject");
            if (dataObjectProp != null)
            {
                var dataObject = dataObjectProp.GetValue(storageObject) as PilotDataObject;
                if (dataObject != null && !string.IsNullOrEmpty(dataObject.DisplayName))
                    return dataObject.DisplayName;
            }

            var nameProp = storageObject.GetType().GetProperty("Name");
            if (nameProp != null)
            {
                var name = nameProp.GetValue(storageObject)?.ToString();
                if (!string.IsNullOrEmpty(name))
                    return name;
            }

            string path = GetFilePath(storageObject);
            if (!string.IsNullOrEmpty(path))
                return Path.GetFileName(path);

            return "";
        }

        private bool GetIsDirectory(object storageObject)
        {
            var prop = storageObject.GetType().GetProperty("IsDirectory");
            if (prop != null)
                return (bool)prop.GetValue(storageObject);

            var field = storageObject.GetType().GetField("IsDirectory",
                System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
            if (field != null)
                return (bool)field.GetValue(storageObject);

            return false;
        }

        private string GetShortAuthorName()
        {
            try
            {
                var person = _repository.GetCurrentPerson();
                if (person == null) return "Unknown";

                string fullName = person.DisplayName;
                if (string.IsNullOrEmpty(fullName))
                {
                    string login = person.Login;
                    return string.IsNullOrEmpty(login) ? "Unknown" : login;
                }

                string[] parts = fullName.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

                if (parts.Length == 0) return "Unknown";

                string result = parts[0];

                if (parts.Length >= 2 && !string.IsNullOrEmpty(parts[1]))
                    result += parts[1].Substring(0, 1);

                if (parts.Length >= 3 && !string.IsNullOrEmpty(parts[2]))
                    result += parts[2].Substring(0, 1);

                return result;
            }
            catch (Exception ex)
            {
                Log("Ошибка в GetShortAuthorName: " + ex.Message);
                return "Unknown";
            }
        }

        private byte[] SignContent(byte[] content, X509Certificate2 certificate)
        {
            ContentInfo contentInfo = new ContentInfo(content);
            SignedCms signedCms = new SignedCms(contentInfo, true);
            CmsSigner signer = new CmsSigner(certificate);

            try
            {
                signedCms.ComputeSignature(signer);
                Log("Подпись создана (автоматический выбор алгоритма)");
            }
            catch (Exception ex)
            {
                Log("Ошибка при подписи (без алгоритма): " + ex.Message);
                signer.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1");
                signedCms.ComputeSignature(signer);
                Log("Подпись создана с алгоритмом SHA256");
            }

            return signedCms.Encode();
        }
    }
}