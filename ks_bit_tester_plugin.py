import logging
import sys
import typing

import idaapi
import ida_bytes
import ida_enum
import ida_kernwin
import ida_netnode
import idc

from PyQt5 import QtCore, QtGui, QtWidgets

ACTION_NAME = "Enum (bit test)"
PLUGIN_DISPLAY_NAME = "Enum from Bit Test"
PLUGIN_HELP = "Searches imported enumerations which match the bit test value"
PLUGIN_SHORTCUT = "Alt+Shift+M"
PLUGIN_COMMENT = "Apply an enumeration from a bit test value"
PLUGIN_MENU_PATH = "Edit/Operand type"
LOG_LEVEL = logging.ERROR

class ApplyEnumHandler(idaapi.action_handler_t):
    
    def __init__(self, *args, **kwargs):
        self.logger = init_logger('apply_enum_handler')
        super().__init__(*args, **kwargs)
        self.logger.debug(f"ApplyEnumHandler initialized.")

    def display_ui(self, bit_test_value):
        # Shift the value to get our search parameter
        enum_value = 1 << int(bit_test_value)
        
        # Go through all loaded enums to see if it's in there
        enum_count = ida_enum.get_enum_qty()
        matches = []
        for i in range(enum_count):
            enum_id = ida_enum.getn_enum(i)
            if not enum_id:
                continue
            enum_is_bf = ida_enum.is_bf(enum_id)
            if enum_is_bf:
                const_id = ida_enum.get_enum_member(enum_id, enum_value, 0, enum_value)
            else:
                const_id = ida_enum.get_enum_member(enum_id, enum_value, 0, 0xFFFFFFFF)
            if const_id != ida_netnode.BADNODE:
                # Looks legitimate, grab the enum name and const name
                const_name = ida_enum.get_enum_member_name(const_id)
                enum_name = ida_enum.get_enum_name(enum_id)
                matches.append((const_name, enum_name))
            
                
        # Populate and show the dialog box
        dialog = BitTesterWidget(hex(enum_value))
        for match in matches:
            const_name, enum_name = match
            dialog.addEnumEntry(const_name, enum_name)
        dialog.table.resizeRowsToContents()
                
        old_timeout = idaapi.set_script_timeout(0)
        res = dialog.exec_()
        idaapi.set_script_timeout(old_timeout)
        if res != QtWidgets.QDialog.Accepted:
            self.logger.debug('Dialog rejected')
            return None, None
        
        self.logger.debug('Dialog accepted. Fetching values.')
        enum_choice, const_choice = dialog.getChoice()
        return enum_choice, const_choice          

    def activate(self, ctx):
        self.logger.debug(f"activate()\n")
        """ This is when we actually get invoked via click """
        # Make sure there's actually an untyped value we can use on the current line
        value = None
        operand_type = None
        for operand_idx in [0,1]:
            operand_type = idc.get_operand_type(ctx.cur_ea, operand_idx)
            if  operand_type in [idc.o_imm, idc.o_displ]:
                self.logger.debug(f"Found immediate at 0x{ctx.cur_ea:08x}, operand {operand_idx}")
                op_value = idc.get_operand_value(ctx.cur_ea, operand_idx)
                if op_value != -1 and op_value < 64:
                    value = int(op_value)
                    break
        
        if value is None:
            # Don't pop the form.
            self.logger.info(f"No immediate values less than 64 to check on current line.")
            return

        # Make a form with all detected instances of the enumeration values
        self.logger.debug(f"Launching UI for immediate 0x{value:08x}")
        enum_choice, const_choice = self.display_ui(value)
        if not const_choice:
            return True
        
        # Apply it
        self.logger.debug(f'User wants to apply {const_choice} from {enum_choice}')
        if not ida_bytes.set_forced_operand(ctx.cur_ea, operand_idx, const_choice):
            self.logger.error(f"set_forced_operand failed.")
        return True

    def update(self, ctx):
        self.logger.debug("update()")
        """ This determines whether the action is available """
        # Only valid in the disassembly widget
        if ctx.widget_type != ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        
        # Only valid when there's a selection and the operand types make sense
        return ida_kernwin.ACF_HAS_SELECTION
        
ENUM_HANDLER = None

class bit_tester_plugin_t(idaapi.plugin_t):

    # These members are defined in the plugin_t spec
    # flags = idaapi.PLUGIN_KEEP
    flags = 0
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_DISPLAY_NAME
    wanted_hotkey = ""

    def init(self): 
        # Create the plugin action
        if hasattr(sys.modules['idaapi'], '_ks_bit_tester_installed'):
            return
        action_desc = idaapi.action_desc_t(
            ACTION_NAME,
            PLUGIN_DISPLAY_NAME,
            ENUM_HANDLER,
            PLUGIN_SHORTCUT,
            PLUGIN_COMMENT
        )
        
        if not idaapi.register_action(action_desc):
            raise Exception(f"Failed to register action.")

        # Register in the enum context menu
        if not ida_kernwin.attach_action_to_menu(
            PLUGIN_MENU_PATH,
            ACTION_NAME,
            idaapi.SETMENU_APP
        ):
            raise Exception(f"Failed to attach action to menu.")
        setattr(sys.modules['idaapi'], '_ks_bit_tester_installed', True)
        return idaapi.PLUGIN_OK

    def run(self, arg):
        #idaapi.msg(f"enum_applier_plugin_t:run\n")
        pass

    def term(self):
        #idaapi.msg(f"enum_applier_plugin_t:term\n")
        pass



class BitTesterDataFormat(ida_bytes.data_format_t):
    FORMAT_NAME = 'bittester_data_format'
    def __init__(self):
        self.logger = init_logger('bittester_data_format')
        ida_bytes.data_format_t.__init__(
            self, 
            'py_bittestval',
            1,
            "Bittest"
        )

    def is_present_in_menus(self):
        return True
    
    def printf(self, value, current_ea, operand_num, dtid):
        self.logger.debug(f"Invoked printf with value {value}")
        _, const_choice = ENUM_HANDLER.display_ui(value)
        return const_choice

############################ UTILS #############################
def init_logger(logger_name:typing.AnyStr, log_level=None):
    logger = logging.getLogger(logger_name)
    if logger.handlers:
        # It already exists
        return logger
    formatter = logging.Formatter('[%(asctime)s %(levelname)-9s] %(name)s: %(message)s')
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.setLevel(log_level or LOG_LEVEL)
    logger.addHandler(console)
    logger.setLevel(log_level or LOG_LEVEL)
    return logger

########################### UI STUFF ###########################

class Ui_BitTesterDialog(object):
    
    def __init__(self, valueStr):
        self.logger = init_logger('bittester_ui')
        self.valueStr = valueStr

    def setupUi(self, BitTesterDialog):
        BitTesterDialog.setObjectName("BitTesterDialog")
        BitTesterDialog.resize(600, 400)
        BitTesterDialog.setSizeGripEnabled(True)
        BitTesterDialog.setModal(False)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(BitTesterDialog)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setSizeConstraint(QtWidgets.QLayout.SetMinAndMaxSize)
        self.verticalLayout.setObjectName("verticalLayout")
        self.tableWidget = QtWidgets.QTableWidget(BitTesterDialog)
        self.tableWidget.setEnabled(True)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Ignored, QtWidgets.QSizePolicy.Ignored)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(self.tableWidget.sizePolicy().hasHeightForWidth())
        self.tableWidget.setSizePolicy(sizePolicy)
        self.tableWidget.setMinimumSize(QtCore.QSize(0, 0))
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(10)
        self.tableWidget.setFont(font)
        self.tableWidget.viewport().setProperty("cursor", QtGui.QCursor(QtCore.Qt.ArrowCursor))
        self.tableWidget.setMouseTracking(False)
        self.tableWidget.setFocusPolicy(QtCore.Qt.ClickFocus)
        self.tableWidget.setAutoFillBackground(False)
        self.tableWidget.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tableWidget.setTabKeyNavigation(True)
        self.tableWidget.setProperty("showDropIndicator", False)
        self.tableWidget.setAlternatingRowColors(True)
        self.tableWidget.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.tableWidget.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tableWidget.setShowGrid(False)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(2)
        self.tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignVCenter)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(10)
        item.setFont(font)
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignVCenter)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(10)
        item.setFont(font)
        self.tableWidget.setHorizontalHeaderItem(1, item)
        self.tableWidget.horizontalHeader().setVisible(True)
        self.tableWidget.horizontalHeader().setCascadingSectionResizes(True)
        self.tableWidget.horizontalHeader().setDefaultSectionSize(200)
        self.tableWidget.horizontalHeader().setHighlightSections(True)
        self.tableWidget.horizontalHeader().setMinimumSectionSize(200)
        self.tableWidget.horizontalHeader().setSortIndicatorShown(True)
        self.tableWidget.horizontalHeader().setStretchLastSection(True)
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.verticalHeader().setHighlightSections(True)
        self.tableWidget.verticalHeader().setStretchLastSection(False)
        self.verticalLayout.addWidget(self.tableWidget)
        self.buttonBox = QtWidgets.QDialogButtonBox(BitTesterDialog)
        self.buttonBox.setEnabled(True)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.buttonBox.sizePolicy().hasHeightForWidth())
        self.buttonBox.setSizePolicy(sizePolicy)
        self.buttonBox.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.buttonBox.setAutoFillBackground(False)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setCenterButtons(True)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout.addWidget(self.buttonBox)
        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.retranslateUi(BitTesterDialog)
        self.buttonBox.accepted.connect(BitTesterDialog.accept)
        self.buttonBox.rejected.connect(BitTesterDialog.reject)
        self.tableWidget.cellClicked['int','int'].connect(self.tableWidget.selectRow)
        self.tableWidget.cellDoubleClicked['int','int'].connect(BitTesterDialog.accept)
        QtCore.QMetaObject.connectSlotsByName(BitTesterDialog)

    def retranslateUi(self, BitTesterDialog):
        _translate = QtCore.QCoreApplication.translate
        BitTesterDialog.setWindowTitle(_translate("BitTesterDialog", f"Apply Enum from Bit Test Value: {self.valueStr}"))
        self.tableWidget.setSortingEnabled(True)
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("BitTesterDialog", "Enumeration"))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("BitTesterDialog", "Symbol"))

class BitTesterWidget(QtWidgets.QDialog):
    
    def __init__(self, valueStr, parent=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.logger = init_logger('bittester_widget')
        try:
            self.ui = Ui_BitTesterDialog(valueStr)
            self.ui.setupUi(self)
        except Exception as e:
            self.logger.exception(f'Initialization error: {e}')

    @property
    def table(self):
        return self.ui.tableWidget

    def getChoice(self):
        rowData = self.table.selectedItems()
        if not rowData:
            return None, None
        enumChoice = rowData[0].text()
        constChoice = rowData[1].text()
        return enumChoice, constChoice

    def addEnumEntry(self, constName, enumName):
        curRow = self.table.rowCount()
        self.table.insertRow(curRow)
        self.table.setItem(curRow, 0, QtWidgets.QTableWidgetItem(enumName))
        self.table.setItem(curRow, 1, QtWidgets.QTableWidgetItem(constName))
        
####################### PLUGIN ENTRY #########################
def PLUGIN_ENTRY():
    global ENUM_HANDLER, DATAFMT_HANDLER
    try:
        ENUM_HANDLER = ApplyEnumHandler()
        ida_bytes.register_data_types_and_formats([(BitTesterDataFormat(),)])
        return bit_tester_plugin_t()
    except Exception as e:
        idaapi.msg(f"Failed to initialize plugin: {e}\n")
        raise e