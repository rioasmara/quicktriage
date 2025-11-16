"""
Notification widget for displaying update notifications.
"""

from PySide6.QtWidgets import QWidget, QLabel, QVBoxLayout
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPoint
from PySide6.QtGui import QColor, QPainter, QBrush


class NotificationWidget(QWidget):
    """A toast-style notification widget that appears and fades out."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint |
            Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        
        self.setFixedSize(300, 60)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        
        self.label = QLabel()
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet("""
            QLabel {
                background-color: #1b2d43;
                color: #e5f8ff;
                border: 1px solid #29b6d3;
                border-radius: 6px;
                padding: 8px;
                font-size: 10pt;
                font-weight: 600;
            }
        """)
        layout.addWidget(self.label)
        
        self.fade_animation = QPropertyAnimation(self, b"windowOpacity")
        self.fade_animation.setDuration(300)
        self.fade_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        self.hide_timer = QTimer(self)
        self.hide_timer.setSingleShot(True)
        self.hide_timer.timeout.connect(self.fade_out)
        
        self.hide()
    
    def show_notification(self, message, duration_ms=2000):
        """Show a notification message for the specified duration."""
        self.label.setText(message)
        self.setWindowOpacity(1.0)
        self.show()
        
        # Position in top-right corner of parent
        if self.parent():
            parent_rect = self.parent().geometry()
            x = parent_rect.x() + parent_rect.width() - self.width() - 20
            y = parent_rect.y() + 20
            self.move(x, y)
        
        # Start hide timer
        self.hide_timer.start(duration_ms)
    
    def fade_out(self):
        """Fade out the notification."""
        self.fade_animation.setStartValue(1.0)
        self.fade_animation.setEndValue(0.0)
        self.fade_animation.finished.connect(self.hide)
        self.fade_animation.start()
    
    def paintEvent(self, event):
        """Paint the widget with rounded corners."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QBrush(QColor(0, 0, 0, 0)))  # Transparent background
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(self.rect(), 8, 8)
        super().paintEvent(event)





