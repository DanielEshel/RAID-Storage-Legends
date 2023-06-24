from client.client_logic import *
import client.inputs as inputs
import threading
import wx
import wx.adv
import natsort


class Frame(wx.Frame):
    def __init__(self, parent, title: str, server_ip: str):
        """
        init the frame, make log in, sign up and home panel. stat with home panel.
        :param parent:
        :param title:
        """
        # init base frame
        super(Frame, self).__init__(parent, title=title, size=(800, 600),
                                    style=wx.DEFAULT_FRAME_STYLE ^ wx.RESIZE_BORDER ^ wx.MAXIMIZE_BOX)
        self.SetIcon(wx.Icon("gui_files\\icon.png"))  # set icon
        # self.loading_panel = LoadingPanel(self)
        self.cl = ClientLogic(data_port=1111, server_ip=server_ip)  # add client logic
        self.sizer = wx.BoxSizer(wx.VERTICAL)  # main sizer for panels
        self.login_panel = LoginPanel(self)  # build login panel
        self.sign_up_panel = SignUpPanel(self)  # build sign up panel
        self.home_panel = HomePanel(self)  # build home panel
        # hide unwanted panels
        self.sign_up_panel.Hide()
        self.login_panel.Hide()
        self.home_panel.Hide()

        self.file_upload_progress = None

        self.sizer.Add(self.login_panel, 1, flag=wx.EXPAND)
        self.sizer.Add(self.sign_up_panel, 1, flag=wx.EXPAND)
        self.sizer.Add(self.home_panel, 1, flag=wx.EXPAND)
        self.SetSizer(self.sizer)
        self.Center()

        self.Bind(wx.EVT_CLOSE, self.on_close)

        threading.Thread(target=self.handle_inputs, daemon=True).start()

    def on_close(self, event):
        exit()

    def switch_login(self):
        """
        switch to login screen
        :return:
        """
        # hide all other panels
        self.sign_up_panel.HideWithEffect(wx.SHOW_EFFECT_SLIDE_TO_RIGHT)
        self.home_panel.HideWithEffect(wx.SHOW_EFFECT_SLIDE_TO_RIGHT)
        # set size and show login panel.
        self.login_panel.SetSize(self.GetSize())
        self.login_panel.ShowWithEffect(wx.SHOW_EFFECT_SLIDE_TO_RIGHT)
        self.login_panel.Layout()

    def switch_sign_up(self):
        """
        switch to sign up screen
        :return:
        """
        # hide all other panels
        self.login_panel.HideWithEffect(wx.SHOW_EFFECT_SLIDE_TO_LEFT)
        self.home_panel.HideWithEffect(wx.SHOW_EFFECT_SLIDE_TO_LEFT)
        # set size and show sign up panel.
        self.sign_up_panel.SetSize(self.GetSize())
        self.sign_up_panel.ShowWithEffect(wx.SHOW_EFFECT_SLIDE_TO_LEFT)
        self.sign_up_panel.Layout()

    @staticmethod
    def _clear_inputs(panel):
        """
        clear username and password from login/sign_up panels.
        :param panel:
        :return:
        """
        panel.tc_username.Clear()
        panel.tc_password.Clear()

    def switch_home(self):
        """
        switch to home panel.
        """
        self.cl.get_files()  # ask server user's file list.
        self.cl.get_storage()  # ask server for user's storage status.
        # clear inputs from both panels
        self._clear_inputs(self.login_panel)
        self._clear_inputs(self.sign_up_panel)
        # hide all other panels
        self.sign_up_panel.HideWithEffect(wx.SHOW_EFFECT_EXPAND)
        self.login_panel.HideWithEffect(wx.SHOW_EFFECT_EXPAND)
        # set size and show home panel.
        self.home_panel.SetSize(self.GetSize())
        self.home_panel.ShowWithEffect(wx.SHOW_EFFECT_EXPAND)
        self.home_panel.Layout()
        # refresh home panel to fit new user data.
        self.home_panel.refresh()

    def download_files(self, files: list):
        """
        download list of files from server.
        :param files: list of file names to download.
        """
        self.file_upload_progress = FileProgressFrame(files, 1)
        self.file_upload_progress.Show()
        self.cl.download_files(files)

    def upload_files(self, files: list):
        """
        upload list of files to server.
        :param files: list of files to upload.
        """
        # wx.CallAfter(self.update_progress, i)  # Update the progress bar using the main GUI thread
        self.file_upload_progress = FileProgressFrame(files, 0)
        self.file_upload_progress.Show()

        self.cl.upload_files(files)

    def delete_files(self, files: list):
        """
        delete list of files from server.
        :param files: list of files to delete
        """
        self.cl.delete_files(files)

    def logout(self):
        """
        log out user.
        """
        self.cl.log_out()
        self.switch_login()  # switch back to login panel.

    def change_password(self, new_password):
        if new_password:
            if inputs.valid_password(new_password):
                self.cl.change_password(new_password)
            else:
                wx.MessageBox("password must be alphanumeric and shorter than 20 characters", "Error", wx.OK)
        else:
            wx.MessageBox("password not entered", "Error", wx.OK)

    def handle_inputs(self):
        """
        handle showing logic inputs to user.
        """
        threading.Event.wait(self.cl.connected)  # wait for server connection.
        self.login_panel.Show()  # show login panel
        while True:
            msg = self.cl.user_q.get()
            opcode = msg[0]
            if opcode == '00':  # if login answer
                answer = msg[1]
                if answer == '0':
                    wx.MessageBox("incorrect username or password.", "Error", wx.OK)
                elif answer == '1':
                    self.switch_home()
                elif answer == '2':
                    wx.MessageBox("denied by server.", "Error", wx.OK)
            elif opcode == '01':  # if sign up answer
                answer = msg[1]
                if answer == '0':
                    wx.MessageBox('username is taken.', "Error", wx.OK)
                elif answer == '1':
                    self.switch_home()
                elif answer == '2':
                    wx.MessageBox("denied by server.", "Error", wx.OK)

            elif opcode == '02':  # got files -> refresh home panel
                self.home_panel.files = dict(self.cl.files)
                self.home_panel.refresh()

            elif opcode == '03':  # got storage -> refresh home panel
                self.home_panel.refresh()

            elif opcode == '04':
                file_name, answer = msg[1:]
                if answer == '0':
                    file_name = answer[1]
                    wx.MessageBox(f'could not upload {file_name} because name already exists.', 'Error', wx.OK)
                elif answer == '2':
                    wx.MessageBox(f'not enough space to upload {file_name}.', 'Error', wx.OK)
                elif answer == '3':
                    wx.MessageBox(f'error occurred while attempting to upload {file_name}.', 'Error', wx.OK)

            elif opcode == '05':
                file_name, answer = msg[1], msg[2]
                if answer == '0':
                    wx.MessageBox(f'error while attempting to delete {file_name}', "Error", wx.OK)
                else:
                    self.home_panel.files = dict(self.cl.files)
                    self.home_panel.refresh()  # refresh home screen panel if deleted successfully.

            elif opcode == '10':  # file upload/download progress
                file_name, progress = msg[1], msg[2]
                if self.file_upload_progress is not None:
                    self.file_upload_progress.files_uploading[file_name][0] += progress

                    # Update the progress bar using the main GUI thread
                    wx.CallAfter(self.file_upload_progress.update_progress, progress)
                    wx.CallAfter(self.file_upload_progress.update_file_label, file_name)  # Update the file label

            elif opcode == '11':  # got files upload confirmation.
                file_name, answer = msg[1], msg[2]
                if answer == '1':
                    self.home_panel.files = dict(self.cl.files)
                    self.home_panel.refresh()
                    self.file_upload_progress.files_uploading[file_name][0] += 1
                    wx.CallAfter(self.file_upload_progress.update_progress, 1)
                else:
                    self.file_upload_progress.on_close(None)
                    wx.MessageBox(f'an error occurred while attempting to upload {file_name}. please try again later',
                                  "Error", wx.OK)

            elif opcode == '12':  # got files download confirmation.
                file_name, answer = msg[1], msg[2]
                if answer == '1':
                    self.file_upload_progress.files_uploading[file_name][0] += 1
                    wx.CallAfter(self.file_upload_progress.update_progress, 1)
                else:
                    self.file_upload_progress.on_close(None)
                    wx.MessageBox(f'an error occurred while attempting to download {file_name}. please try again later',
                                  "Error", wx.OK)
            else:
                print(f'\nopcode: {opcode}, msg: {msg}\n')


class LoginPanel(wx.Panel):
    """
    log in screen.
    """
    def __init__(self, parent: Frame):
        """
        init login screen.
        :param parent: parent frame.
        """

        super(LoginPanel, self).__init__(parent, size=parent.GetSize())  # build panel
        self.parent = parent
        # vertical sizer to contain username and password inputs, login button and sign up options
        self.vs = wx.BoxSizer(wx.VERTICAL)
        self.main_sizer = wx.BoxSizer(wx.VERTICAL)  # main sizer for panel.
        self.logo_sizer = wx.BoxSizer()

        png = wx.Image('gui_files\\logo.png', wx.BITMAP_TYPE_ANY).ConvertToBitmap()  # logo png bitmap
        logo = wx.StaticBitmap(self, -1, png, (100, 5), (png.GetWidth(), png.GetHeight()))  # show bitmap
        self.logo_sizer.Add(logo, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)  # add to sizer.

        # build username textctrl
        self.tc_username = wx.TextCtrl(self)
        self.tc_username.SetHint('username')
        # build password textctrl
        self.tc_password = wx.TextCtrl(self, style=wx.TE_PASSWORD)
        self.tc_password.SetHint('password')
        # build and bind login button
        self.bt_login = wx.Button(self, label='Login')
        self.bt_login.Bind(wx.EVT_BUTTON, self.on_login)
        # build and bind sign up url
        self.st_sign_up = wx.StaticText(self, label="Don't have an account? ")
        self.hlc_sign_up = wx.adv.HyperlinkCtrl(self, label='Sign up')
        self.Bind(wx.adv.EVT_HYPERLINK, self.on_signup, self.hlc_sign_up)

        # add to vertical sizer with wanted spaces
        self.vs.Add(self.tc_username, 0, wx.EXPAND)
        self.vs.Add(self.tc_password, 0, wx.EXPAND)
        self.vs.Add(self.bt_login, 0, wx.ALIGN_CENTER_VERTICAL | wx.EXPAND)
        self.vs.AddSpacer(10)

        # sizer for sign up url
        h_text_sizer = wx.BoxSizer(wx.HORIZONTAL)
        h_text_sizer.AddMany([(self.st_sign_up, 0, wx.EXPAND), (self.hlc_sign_up, 0, wx.EXPAND)])
        self.vs.Add(h_text_sizer, 0, wx.ALIGN_CENTER_VERTICAL)

        # add all sizers to main panel sizer
        self.main_sizer.Add(self.logo_sizer, 0, wx.ALIGN_CENTER_HORIZONTAL)
        self.main_sizer.AddStretchSpacer(1)
        self.main_sizer.Add(self.vs, 0, wx.ALIGN_CENTER)
        self.main_sizer.AddStretchSpacer(1)
        self.main_sizer.AddStretchSpacer(1)
        # set panel to main sizer.
        self.SetSizerAndFit(self.main_sizer)

    def on_login(self, event):
        username = self.tc_username.GetValue()
        password = self.tc_password.GetValue()
        if username:
            if password:
                if inputs.valid_username(username):
                    if inputs.valid_password(password):
                        self.parent.cl.login(username, password)
                    else:
                        wx.MessageBox("password must be alphanumeric and shorter than 20 characters", "Error", wx.OK)

                else:
                    wx.MessageBox("username must be alphanumeric and shorter than 20 characters", "Error", wx.OK)

            else:
                wx.MessageBox("password not entered", "Error", wx.OK)

        else:
            wx.MessageBox("username not entered", "Error", wx.OK)

    def on_signup(self, event):
        self.SetSize(self.parent.GetSize())

        self.parent.switch_sign_up()
        self.tc_username.ChangeValue('')
        self.tc_password.ChangeValue('')


class SignUpPanel(wx.Panel):
    """
    sign up screen.
    """
    def __init__(self, parent: Frame):
        """
        init sign up screen.
        :param parent: parent frame.
        """

        super(SignUpPanel, self).__init__(parent, size=parent.GetSize())
        self.parent = parent
        self.vs = wx.BoxSizer(wx.VERTICAL)
        self.main_sizer = wx.BoxSizer(wx.VERTICAL)
        self.logo_sizer = wx.BoxSizer()

        # build logo
        png = wx.Image('gui_files\\logo.png', wx.BITMAP_TYPE_ANY).ConvertToBitmap()
        logo = wx.StaticBitmap(self, -1, png, (100, 5), (png.GetWidth(), png.GetHeight()))
        self.logo_sizer.Add(logo, 0, wx.ALIGN_CENTER_HORIZONTAL | wx.ALL, 5)

        # sign up instructions text
        instruction_text = wx.StaticText(self, label='Create an account')

        # username input
        self.tc_username = wx.TextCtrl(self)
        self.tc_username.SetHint('username')
        # password input
        self.tc_password = wx.TextCtrl(self, style=wx.TE_PASSWORD)
        self.tc_password.SetHint('password')
        # login button
        self.bt_login = wx.Button(self, label='Sign up')
        self.bt_login.Bind(wx.EVT_BUTTON, self.on_signup)
        self.st_login = wx.StaticText(self, label="already have an account? ")

        # login text url option.
        self.hlc_login = wx.adv.HyperlinkCtrl(self, label='Login')
        self.Bind(wx.adv.EVT_HYPERLINK, self.on_login, self.hlc_login)

        # add to sizer
        self.vs.Add(self.tc_username, 0, wx.EXPAND)
        self.vs.Add(self.tc_password, 0, wx.EXPAND)
        self.vs.Add(self.bt_login, 0, wx.ALIGN_CENTER_VERTICAL | wx.EXPAND)
        self.vs.AddSpacer(10)
        h_text_sizer = wx.BoxSizer(wx.HORIZONTAL)
        h_text_sizer.AddMany([(self.st_login, 0, wx.EXPAND), (self.hlc_login, 0, wx.EXPAND)])
        self.vs.Add(h_text_sizer, 0, wx.ALIGN_CENTER_VERTICAL)

        # add all sizers to main panel sizer
        self.main_sizer.Add(self.logo_sizer, 0, wx.ALIGN_CENTER_HORIZONTAL)
        self.main_sizer.AddStretchSpacer(1)
        self.main_sizer.Add(instruction_text, 0, wx.ALIGN_CENTER_HORIZONTAL)
        self.main_sizer.AddSpacer(10)
        self.main_sizer.Add(self.vs, 0, wx.ALIGN_CENTER)
        self.main_sizer.AddStretchSpacer(1)
        self.main_sizer.AddStretchSpacer(1)
        self.main_sizer.AddStretchSpacer(1)
        # set main sizer
        self.SetSizerAndFit(self.main_sizer)

    def on_login(self, event):
        """
        user pressed login button (wants to login to existing acc. instead of signing up), switch to login screen
        """
        self.SetSize(self.parent.GetSize())
        self.parent.switch_login()
        self.tc_username.ChangeValue('')
        self.tc_password.ChangeValue('')

    def on_signup(self, event):
        """
        sign up as a new account
        """
        # get values
        username = self.tc_username.GetValue()
        password = self.tc_password.GetValue()
        if username:
            if password:
                if inputs.valid_username(username):
                    if inputs.valid_password(password):
                        # call ClientLogic's sign up function.
                        self.parent.cl.sign_up(username, password)
                    else:
                        wx.MessageBox("password must be alphanumeric and shorter than 20 characters", "Error", wx.OK)

                else:
                    wx.MessageBox("username must be alphanumeric and shorter than 20 characters", "Error", wx.OK)

            else:
                wx.MessageBox("password not entered", "Error", wx.OK)

        else:
            wx.MessageBox("username not entered", "Error", wx.OK)


class HomePanel(wx.Panel):
    """
    home screen.
    """
    def __init__(self, parent):
        """
        init home screen.
        :param parent: parent frame.
        """

        super(HomePanel, self).__init__(parent, size=parent.GetSize())
        self.files = dict()
        self.parent = parent

        # build sizers
        self.main_sizer = wx.BoxSizer(wx.VERTICAL)
        self.toolbar_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.files_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.header_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.options_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.footer_sizer = wx.BoxSizer(wx.HORIZONTAL)
        tool_width, tool_height = 20, 20

        # welcome header text
        self.st_welcome = wx.StaticText(self, label='')
        self.header_sizer.Add(self.st_welcome, flag=wx.ALIGN_CENTER_HORIZONTAL)

        # change password url
        self.hlc_change_password = wx.adv.HyperlinkCtrl(self, label='change password')
        self.options_sizer.Add(self.hlc_change_password, border=10, flag=wx.RIGHT)
        self.hlc_change_password.Bind(wx.adv.EVT_HYPERLINK, self.on_change_password)

        # logout button
        bitmap = wx.Bitmap('gui_files\\logout_icon.png')
        image = wx.Bitmap.ConvertToImage(bitmap)
        image = image.Scale(tool_width, tool_height, wx.IMAGE_QUALITY_HIGH)
        bitmap = wx.Image.ConvertToBitmap(image)
        self.bt_logout = wx.Button(self, size=bitmap.GetSize(), style=wx.NO_BORDER)
        self.bt_logout.SetBitmap(bitmap)
        self.options_sizer.Add(self.bt_logout, border=15, flag=wx.RIGHT)
        self.bt_logout.Bind(wx.EVT_BUTTON, self.on_logout)

        # download button
        bitmap = wx.Bitmap('gui_files\\download_icon.png')
        image = wx.Bitmap.ConvertToImage(bitmap)
        image = image.Scale(tool_width, tool_height, wx.IMAGE_QUALITY_HIGH)
        bitmap = wx.Image.ConvertToBitmap(image)
        self.bt_download_files = wx.Button(self, size=bitmap.GetSize(), style=wx.NO_BORDER)
        self.bt_download_files.SetBitmap(bitmap)
        self.toolbar_sizer.Add(self.bt_download_files, border=10, flag=wx.LEFT)
        self.bt_download_files.Bind(wx.EVT_BUTTON, self.on_download)

        # upload button
        bitmap = wx.Bitmap('gui_files\\upload_icon.png')
        image = wx.Bitmap.ConvertToImage(bitmap)
        image = image.Scale(tool_width, tool_height, wx.IMAGE_QUALITY_HIGH)
        bitmap = wx.Image.ConvertToBitmap(image)
        self.bt_upload_files = wx.Button(self, size=bitmap.GetSize(), style=wx.NO_BORDER)
        self.bt_upload_files.SetBitmap(bitmap)
        self.toolbar_sizer.Add(self.bt_upload_files, border=10, flag=wx.LEFT | wx.EXPAND)
        self.bt_upload_files.Bind(wx.EVT_BUTTON, self.on_upload)

        # delete button
        bitmap = wx.Bitmap('gui_files\\del_icon.png')
        image = wx.Bitmap.ConvertToImage(bitmap)
        image = image.Scale(tool_width, tool_height, wx.IMAGE_QUALITY_HIGH)
        bitmap = wx.Image.ConvertToBitmap(image)
        self.bt_del_files = wx.Button(self, size=bitmap.GetSize(), style=wx.NO_BORDER)
        self.bt_del_files.SetBitmap(bitmap)
        self.toolbar_sizer.Add(self.bt_del_files, border=10, flag=wx.LEFT)
        self.bt_del_files.Bind(wx.EVT_BUTTON, self.on_delete)

        #  files list
        self.lc_files = wx.ListCtrl(self, -1, style=wx.LC_REPORT | wx.LC_SINGLE_SEL, size=(self.GetSize()[0] - 35,
                                                                                           self.GetSize()[1]-120))
        self.lc_files.InsertColumn(0, 'name', wx.LIST_FORMAT_LEFT)
        self.lc_files.InsertColumn(1, 'size', wx.LIST_FORMAT_RIGHT)
        self.col_name_width = 300
        self.col_size_width = 100
        self.lc_files.SetColumnWidth(0, self.col_name_width)
        self.lc_files.SetColumnWidth(1, self.col_size_width)
        self.files_sizer.Add(self.lc_files, border=10, flag=wx.LEFT | wx.EXPAND)

        # storage data
        self.st_storage = wx.StaticText(self, label='')
        self.footer_sizer.Add(self.st_storage, flag=wx.ALIGN_CENTER_VERTICAL)

        # bind to main sizer.
        self.main_sizer.Add(self.options_sizer, border=10, flag=wx.ALIGN_RIGHT | wx.RIGHT)
        self.main_sizer.Add(self.header_sizer, flag=wx.ALIGN_CENTER_HORIZONTAL)
        self.main_sizer.Add(self.toolbar_sizer, flag=wx.EXPAND)
        self.main_sizer.AddSpacer(5)
        self.main_sizer.Add(self.files_sizer, flag=wx.EXPAND)
        self.main_sizer.AddSpacer(3)
        self.main_sizer.Add(self.footer_sizer, flag=wx.ALIGN_LEFT | wx.LEFT | wx.BOTTOM, border=10)

        self.SetSizer(self.main_sizer)
        self.Layout()

    def refresh(self):
        """
        refresh user's data.
        """
        units = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB']

        # welcome
        self.st_welcome.SetLabel(f'Welcome {self.parent.cl.username}')

        # handle files list
        self.lc_files.DeleteAllItems()  # remove all files from current list.
        file_names = natsort.natsorted(self.files)
        for name in file_names:
            size = self.files[name]
            unit_index = 0
            while len(str(int(size))) > 3 and unit_index < len(units) - 1:
                unit_index += 1
                size /= 1000

            index = self.lc_files.InsertItem(self.lc_files.GetItemCount(), name)
            self.lc_files.SetItem(index, 1, f'{size} {units[unit_index]}')

        # handle storage status
        used = int(self.parent.cl.storage_used)
        total = int(self.parent.cl.total_storage)
        if total <= 0:
            percent_remaining = 0
        else:
            percent_remaining = 100 - (used/total) * 100
        used_unit_index = 0
        total_unit_index = 0
        while len(str(int(used))) > 3 and used_unit_index < len(units) - 1:
            used_unit_index += 1
            used /= 1000
        while len(str(int(total))) > 3 and total_unit_index < len(units) - 1:
            total_unit_index += 1
            total /= 1000

        self.st_storage.SetLabel(f'Used {used} {units[used_unit_index]} out of {total} {units[total_unit_index]} - '
                                 f'{percent_remaining*100//1/100}% remaining.')
        self.Layout()

    def on_logout(self, event):
        """
        call parent logout function when clicked on logout link.
        """
        self.parent.logout()

    def on_change_password(self, event):
        """
        build and handle change password dialogue
        """
        frame = wx.Frame(None, -1, 'win.py')
        frame.SetSize(0, 0, 200, 50)

        # build dialogue
        dlg = wx.TextEntryDialog(frame, f'enter new password for {self.parent.cl.username}', 'Change password')
        if dlg.ShowModal() == wx.ID_OK:
            # change password if pressed confirmation button.
            self.parent.change_password(dlg.GetValue())

    def on_download(self, event):
        """
        handle user file download request.
        """
        # get first file from shown file list.
        selected_item = self.lc_files.GetFirstSelected()
        if selected_item == -1:
            wx.MessageBox("No files selected for download.", "Error", wx.OK)
        else:
            # get the rest of the selected files.
            files_to_download = []
            while selected_item != -1:
                files_to_download.append(self.lc_files.GetItemText(selected_item, 0))
                selected_item = self.lc_files.GetNextSelected(selected_item)
            # call parent's download function with file list.
            self.parent.download_files(files_to_download)

    def on_upload(self, event):
        """
        handle user's upload request.
        """
        #  open file selection dialogue.
        with wx.FileDialog(self, "Open file", style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as fileDialog:

            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return  # the user changed their mind

            # Proceed loading the files chosen by the user
            path_names = fileDialog.GetPaths()
            self.parent.upload_files(path_names)

    def on_delete(self, event):
        """
        handle user's files deletion request.
        """
        # get first selected file
        selected_item = self.lc_files.GetFirstSelected()

        if selected_item == -1:
            wx.MessageBox("No files selected.", "Error", wx.OK)
        else:
            # get the rest of the files.
            files_to_delete = []
            while selected_item != -1:
                files_to_delete.append(self.lc_files.GetItemText(selected_item, 0))
                selected_item = self.lc_files.GetNextSelected(selected_item)

            # ask for deletion confirmation.
            answer = wx.MessageBox(f"Are you sure you want to permanently delete the following"
                                   f" files: \n{files_to_delete}", 'Delete File', wx.YES_NO)
            if answer == wx.YES:  # if confirmed, call parent's file deletion function.
                self.parent.delete_files(files_to_delete)


class FileProgressFrame(wx.Frame):

    labels = {
        0: 'Uploading File: ',
        1: 'Downloading File'
    }

    def __init__(self, files, style):
        """
        upload and download progress bar frame.
        :param files: list of files that are being transferred
        :param type: 0 for upload, 1 for download
        """
        wx.Frame.__init__(self, None, title="File Transfer", size=(400, 150),
                          style=wx.DEFAULT_DIALOG_STYLE ^ wx.CLOSE_BOX)
        self.panel = wx.Panel(self)
        self.style = style
        main_sizer = wx.BoxSizer(wx.VERTICAL)  # Main vertical sizer for the frame
        self.files_uploading = {}

        self.bytes_uploaded = 0
        self.total_bytes = 0
        for file in files:
            if '\\' in file:
                name_div = file.rfind('\\')  # get starting index of file name.
                file_name = file[name_div + 1:]
            else:
                file_name = file
            size = get_encrypted_size(os.path.getsize(file))
            self.files_uploading[file_name] = [0, size]
            self.total_bytes += size + 1

        self.file_label = wx.StaticText(self.panel, label=f"{self.labels[self.style]}: ")
        self.progress_bar = wx.Gauge(self.panel, style=wx.GA_HORIZONTAL)
        self.progress_bar.SetRange(100)  # Set the maximum value of the progress bar

        main_sizer.Add(self.file_label, 0, wx.ALIGN_CENTER | wx.ALIGN_CENTER_HORIZONTAL)  # Add file label to main sizer
        main_sizer.Add(self.progress_bar, 0, wx.EXPAND | wx.ALL, 10)  # Add progress bar to main sizer

        self.panel.SetSizer(main_sizer)  # Set main sizer for the panel

        self.CenterOnScreen()  # Center the frame on the screen

    def update_progress(self, progress):
        """
        update progress bar
        :param progress: progress to add (number of bytes transferred)
        """
        self.bytes_uploaded += progress
        percentage = int((self.bytes_uploaded / self.total_bytes) * 100)
        self.progress_bar.SetValue(percentage)
        if percentage == 100:
            self.Close()

    def update_file_label(self, file_name):
        """
        update file name label.
        :param file_name: name of file to update label to.
        """
        self.file_label.SetLabel(f"{self.labels[self.style]}: {file_name}")
        self.panel.Layout()

    def on_close(self, event):
        self.Destroy()


class App(wx.App):

    def __init__(self):

        super().__init__()

    def OnInit(self):
        with open('server_ip.txt', 'r') as fp:
            server_ip = fp.read().strip()
        self.frame = Frame(parent=None, title='RAID STORAGE LEGENDS', server_ip=server_ip)
        self.frame.Show()
        return True


def main():
    app = App()
    app.MainLoop()


if __name__ == '__main__':
    main()
