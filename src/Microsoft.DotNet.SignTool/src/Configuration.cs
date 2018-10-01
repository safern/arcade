// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.Versioning;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

namespace Microsoft.DotNet.SignTool
{
    internal class Configuration
    {
        private readonly TaskLoggingHelper _log;

        private readonly string[] _explicitSignList;

        /// <summary>
        /// This store content information for container files.
        /// Key is the content hash of the file.
        /// </summary>
        private readonly Dictionary<ImmutableArray<byte>, ZipData> _zipDataMap;

        /// <summary>
        /// Path to where container files will be extracted.
        /// </summary>
        private readonly string _pathToContainerUnpackingDirectory;

        /// <summary>
        /// Path to where Signing Suggestion file -> certificate mapping will be stored.
        /// </summary>
        private readonly string _pathToSigningSuggestions;

        /// <summary>
        /// This enable the overriding of the default certificate for a given file+token+target_framework.
        /// It also contains a SignToolConstants.IgnoreFileCertificateSentinel flag in the certificate name in case the file does not need to be signed
        /// for that 
        /// </summary>
        private readonly Dictionary<ExplicitCertificateKey, string> _explicitCertificates;

        /// <summary>
        /// Used to look for signing information when we have the PublicKeyToken of a file.
        /// </summary>
        private readonly Dictionary<string, SignInfo> _defaultSignInfoForPublicKeyToken;

        /// <summary>
        /// A list of all of the binaries that MUST be signed.
        /// </summary>
        private readonly List<FileSignInfo> _filesToSign;

        /// <summary>
        /// Mapping of ".ext" to certificate. Files that have an extension on this map
        /// will be signed using the specified certificate.
        /// </summary>
        private readonly Dictionary<string, SignInfo> _fileExtensionSignInfo;

        private readonly Dictionary<SignedFileContentKey, FileSignInfo> _filesByContentKey;

        /// <summary>
        /// A list of files whose content needs to be overwritten by signed content from a different file.
        /// Copy the content of file with full path specified in Key to file with full path specified in Value.
        /// </summary>
        internal List<KeyValuePair<string, string>> _filesToCopy;

        /// <summary>
        /// Contains the list of files that were discovered but doesn't have explicit
        /// signing information. If this is not empty by the end of the file search 
        /// the signing process will be aborted.
        /// </summary>
        private List<KeyValuePair<string, string>> _filesMissingCertificate;

        public Configuration(string tempDir, string[] explicitSignList, Dictionary<string, SignInfo> defaultSignInfoForPublicKeyToken,
            Dictionary<ExplicitCertificateKey, string> explicitCertificates, Dictionary<string, SignInfo> extensionSignInfo, TaskLoggingHelper log)
        {
            Debug.Assert(tempDir != null);
            Debug.Assert(explicitSignList != null && !explicitSignList.Any(i => i == null));
            Debug.Assert(defaultSignInfoForPublicKeyToken != null);
            Debug.Assert(explicitCertificates != null);

            _pathToContainerUnpackingDirectory = Path.Combine(tempDir, "ContainerSigning");
            _pathToSigningSuggestions = Path.Combine(tempDir, "SigningSuggestions.props");
            _log = log;
            _defaultSignInfoForPublicKeyToken = defaultSignInfoForPublicKeyToken;
            _explicitCertificates = explicitCertificates;
            _fileExtensionSignInfo = extensionSignInfo;
            _filesToSign = new List<FileSignInfo>();
            _filesToCopy = new List<KeyValuePair<string, string>>();
            _zipDataMap = new Dictionary<ImmutableArray<byte>, ZipData>(ByteSequenceComparer.Instance);
            _filesByContentKey = new Dictionary<SignedFileContentKey, FileSignInfo>();
            _explicitSignList = explicitSignList;
            _filesMissingCertificate = new List<KeyValuePair<string, string>>();
        }

        internal BatchSignInput GenerateListOfFiles()
        {
            foreach (var fullPath in _explicitSignList)
            {
                TrackFile(fullPath, ContentUtil.GetContentHash(fullPath), isNested: false);
            }

            if (_filesMissingCertificate.Count > 0)
            {
                _log.LogError($"Discovered unsigned files that do not have assigned certificates. " +
                    $"To fix this issue add missing entries to Signing.props. The list of files and " +
                    $"suggested certificates are listed in {_pathToSigningSuggestions}");

                using (StreamWriter outputFile = new StreamWriter(_pathToSigningSuggestions, true))
                {
                    outputFile.WriteLine("<!-- The file -> certificate mapping below was determined heuristically " +
                        "and must be reviewed before they are put in production code. --> ");

                    outputFile.WriteLine("<Project>");
                    outputFile.WriteLine("  <ItemGroup>");

                    foreach (var item in _filesMissingCertificate)
                    {
                        outputFile.WriteLine($"     <FileSignInfo Include='{item.Key}' CertificateName='{item.Value}' />");
                    }

                    outputFile.WriteLine("  </ItemGroup>");
                    outputFile.WriteLine("</Project>");
                }
            }

            return new BatchSignInput(_filesToSign.ToImmutableArray(), _zipDataMap.ToImmutableDictionary(ByteSequenceComparer.Instance), _filesToCopy.ToImmutableArray());
        }

        private FileSignInfo TrackFile(string fullPath, ImmutableArray<byte> contentHash, bool isNested)
        {
            var fileSignInfo = ExtractSignInfo(fullPath, contentHash, suggestedCertificate);

            var key = new SignedFileContentKey(contentHash, Path.GetFileName(fullPath));

            if (_filesByContentKey.TryGetValue(key, out var existingSignInfo))
            {
                // If we saw this file already we wouldn't call TrackFile unless this is a top-level file.
                Debug.Assert(!isNested);

                // Copy the signed content to the destination path.
                _filesToCopy.Add(new KeyValuePair<string, string>(existingSignInfo.FullPath, fullPath));
                return fileSignInfo;
            }

            if (FileSignInfo.IsZipContainer(fullPath))
            {
                Debug.Assert(!_zipDataMap.ContainsKey(contentHash));

                if (TryBuildZipData(fileSignInfo, out var zipData))
                {
                    _zipDataMap[contentHash] = zipData;
                }
            }

            _filesByContentKey.Add(key, fileSignInfo);

            if (fileSignInfo.SignInfo.ShouldSign)
            {
                _filesToSign.Add(fileSignInfo);
            }

            return fileSignInfo;
        }

        private FileSignInfo ExtractSignInfo(string fullPath, ImmutableArray<byte> hash, string suggestedCertificate)
        {
            var targetFramework = string.Empty;
            var publicKeyToken = string.Empty;
            var isAlreadySigned = false;

            if (FileSignInfo.IsPEFile(fullPath))
            {
                using (var stream = File.OpenRead(fullPath))
                {
                    isAlreadySigned = ContentUtil.IsAuthenticodeSigned(stream);
                }

                GetPEInfo(fullPath, out var isManaged, out publicKeyToken, out targetFramework);
            }

            var certificateName = string.Empty;
            var fileName = Path.GetFileName(fullPath);
            if (_explicitCertificates.TryGetValue(new ExplicitCertificateKey(fileName, publicKeyToken, targetFramework), out certificateName) ||
                _explicitCertificates.TryGetValue(new ExplicitCertificateKey(fileName, publicKeyToken), out certificateName) ||
                _explicitCertificates.TryGetValue(new ExplicitCertificateKey(fileName), out certificateName))
            {
                // Should we ignore this file?
                if (certificateName.Equals(SignToolConstants.IgnoreFileCertificateSentinel, StringComparison.OrdinalIgnoreCase))
                {
                    return new FileSignInfo(fullPath, hash, SignInfo.Ignore);
                }

                if (isAlreadySigned &&
                    !certificateName.Equals(SignToolConstants.Certificate_Microsoft3rdPartyAppComponentDual, StringComparison.OrdinalIgnoreCase) &&
                    !certificateName.Equals(SignToolConstants.Certificate_Microsoft3rdPartyAppComponentSha2, StringComparison.OrdinalIgnoreCase))
                {
                    _log.LogMessage(MessageImportance.Low, $"Asked to sign this file but it was already signed: {fullPath}");
                    return new FileSignInfo(fullPath, hash, SignInfo.AlreadySigned);
                }

                return new FileSignInfo(fullPath, hash, new SignInfo(certificateName));
            }
            else
            {
                if (isAlreadySigned)
                {
                    _log.LogMessage(MessageImportance.Low, $"Skipping already signed file {fullPath}");
                    return new FileSignInfo(fullPath, hash, SignInfo.AlreadySigned);
                }
                else
                {
                    _filesMissingCertificate.Add(new KeyValuePair<string, string>(fileName, suggestedCertificate));
                    return new FileSignInfo(fullPath, hash, SignInfo.Ignore);
                }
            }
        }

        private static void GetPEInfo(string fullPath, out bool isManaged, out string publicKeyToken, out string targetFramework)
        {
            AssemblyName assemblyName;
            try
            {
                assemblyName = AssemblyName.GetAssemblyName(fullPath);
                isManaged = true;
            }
            catch
            {
                isManaged = false;
                publicKeyToken = string.Empty;
                targetFramework = string.Empty;
                return;
            }

            var pktBytes = assemblyName.GetPublicKeyToken();

            publicKeyToken = (pktBytes == null || pktBytes.Length == 0) ? string.Empty : string.Join("", pktBytes.Select(b => b.ToString("x2")));
            targetFramework = GetTargetFrameworkName(fullPath);
        }

        private static string GetTargetFrameworkName(string filePath)
        {
            using (var stream = File.OpenRead(filePath))
            using (var pereader = new PEReader(stream))
            {
                if (pereader.HasMetadata)
                {
                    var metadataReader = pereader.GetMetadataReader();

                    var assemblyDef = metadataReader.GetAssemblyDefinition();
                    foreach (var attributeHandle in assemblyDef.GetCustomAttributes())
                    {
                        var attribute = metadataReader.GetCustomAttribute(attributeHandle);
                        if (QualifiedNameEquals(metadataReader, attribute, "System.Runtime.Versioning", "TargetFrameworkAttribute"))
                        {
                            return new FrameworkName(GetTargetFrameworkAttributeValue(metadataReader, attribute)).FullName;
                        }
                    }
                }
            }

            return null;
        }

        private static bool QualifiedNameEquals(MetadataReader reader, CustomAttribute attribute, string namespaceName, string typeName)
        {
            bool qualifiedNameEquals(StringHandle nameHandle, StringHandle namespaceHandle)
                => reader.StringComparer.Equals(nameHandle, typeName) && reader.StringComparer.Equals(namespaceHandle, namespaceName);

            var ctorHandle = attribute.Constructor;
            switch (ctorHandle.Kind)
            {
                case HandleKind.MemberReference:
                    var container = reader.GetMemberReference((MemberReferenceHandle)ctorHandle).Parent;
                    switch (container.Kind)
                    {
                        case HandleKind.TypeReference:
                            var containerRef = reader.GetTypeReference((TypeReferenceHandle)container);
                            return qualifiedNameEquals(containerRef.Name, containerRef.Namespace);

                        case HandleKind.TypeDefinition:
                            var containerDef = reader.GetTypeDefinition((TypeDefinitionHandle)container);
                            return qualifiedNameEquals(containerDef.Name, containerDef.Namespace);

                        default:
                            return false;
                    }

                case HandleKind.MethodDefinition:
                    var typeDef = reader.GetTypeDefinition(reader.GetMethodDefinition((MethodDefinitionHandle)ctorHandle).GetDeclaringType());
                    return qualifiedNameEquals(typeDef.Name, typeDef.Namespace);

                default:
                    return false;
            }
        }

        private sealed class DummyCustomAttributeTypeProvider : ICustomAttributeTypeProvider<object>
        {
            public static readonly DummyCustomAttributeTypeProvider Instance = new DummyCustomAttributeTypeProvider();
            public object GetPrimitiveType(PrimitiveTypeCode typeCode) => null;
            public object GetSystemType() => null;
            public object GetSZArrayType(object elementType) => null;
            public object GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) => null;
            public object GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) => null;
            public object GetTypeFromSerializedName(string name) => null;
            public PrimitiveTypeCode GetUnderlyingEnumType(object type) => default;
            public bool IsSystemType(object type) => false;
        }

        private static string GetTargetFrameworkAttributeValue(MetadataReader reader, CustomAttribute attribute)
        {
            var value = attribute.DecodeValue(DummyCustomAttributeTypeProvider.Instance);
            return (value.FixedArguments.Length == 1) ? value.FixedArguments[0].Value as string : null;
        }

        /// <summary>
        /// Build up the <see cref="ZipData"/> instance for a given zip container. This will also report any consistency
        /// errors found when examining the zip archive.
        /// </summary>
        private bool TryBuildZipData(FileSignInfo zipFileSignInfo, out ZipData zipData)
        {
            Debug.Assert(zipFileSignInfo.IsZipContainer());

            try
            {
                using (var archive = new ZipArchive(File.OpenRead(zipFileSignInfo.FullPath), ZipArchiveMode.Read))
                {
                    var nestedParts = new List<ZipPart>();

                    foreach (ZipArchiveEntry entry in archive.Entries)
                    {
                        string relativePath = entry.FullName;
                        string extension = Path.GetExtension(relativePath);

                        if (!_fileExtensionSignInfo.TryGetValue(extension, out var extensionSignInfo) || !extensionSignInfo.ShouldSign)
                        {
                            continue;
                        }

                        ImmutableArray<byte> contentHash;
                        using (var stream = entry.Open())
                        {
                            contentHash = ContentUtil.GetContentHash(stream);
                        }

                        // if we already encountered file that hash the same content we can reuse its signed version when repackaging the container.
                        string fileName = Path.GetFileName(relativePath);
                        if (!_filesByContentKey.TryGetValue(new SignedFileContentKey(contentHash, fileName), out var fileSignInfo))
                        {
                            string tempDir = Path.Combine(_pathToContainerUnpackingDirectory, ContentUtil.HashToString(contentHash));
                            string tempPath = Path.Combine(tempDir, Path.GetFileName(relativePath));
                            Directory.CreateDirectory(tempDir);

                            using (var stream = entry.Open())
                            using (var tempFileStream = File.OpenWrite(tempPath))
                            {
                                stream.CopyTo(tempFileStream);
                            }

                            fileSignInfo = TrackFile(tempPath, contentHash, isNested: true);
                        }

                        if (fileSignInfo.SignInfo.ShouldSign)
                        {
                            nestedParts.Add(new ZipPart(relativePath, fileSignInfo));
                        }
                    }

                    zipData = new ZipData(zipFileSignInfo, nestedParts.ToImmutableArray());

                    return true;
                }
            }
            catch (Exception e)
            {
                _log.LogErrorFromException(e);
                zipData = null;
                return false;
            }
        }
    }
}
