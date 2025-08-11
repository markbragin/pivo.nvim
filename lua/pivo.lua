local M = {}

local PASSWORDS = {}
local EXT = ".gpg"
local PATTERN = "*" .. EXT
local GROUP = "Pivo"

if vim.fn.executable("gpg") == 0 then
  vim.notify("Pivo: 'gpg' executable not found", vim.log.levels.ERROR)
  return
end

---@param prompt string
---@return string
local get_password = function(prompt)
  local pass = vim.fn.inputsecret(prompt)
  vim.defer_fn(function() vim.cmd("echon ' '") end, 1000)
  return pass
end

---@param confirm boolean Ask for confirmation
---@param silent boolean Suppress error msg
---@return string | nil
local prompt_password = function(confirm, silent)
  local pass = get_password("Password: ")
  if string.len(pass) == 0 then
    if not silent then
      vim.notify("Pivo: empty password", vim.log.levels.ERROR)
    end
    return nil
  end

  if confirm then
    local pass2 = get_password("Confirm password: ")
    if pass ~= pass2 then
      vim.notify("Pivo: passwords don't match", vim.log.levels.WARN)
      return nil
    end
  end

  return pass
end

--- Whether str ends with suffix
---
---@param str string
---@param suffix string
---@return boolean
local endswith = function(str, suffix)
  if string.sub(str, - #suffix) == suffix then
    return true
  else
    return false
  end
end

local clear_cur_buf = function()
  vim.cmd("%d")
end

---@param flag boolean
local set_cur_buf_modifiable = function(flag)
  vim.api.nvim_set_option_value("modifiable", flag, { scope = "local", buf = 0 })
end

---Sets current buffer filetype.
---If filename ends with EXT (.gpg?) it strips for filetype detection
local set_cur_buf_filetype = function()
  local filename = vim.fn.expand("%:p")

  if string.sub(filename, - #EXT) == EXT then
    filename = string.sub(filename, 1, #filename - #EXT)
  end

  local ft = vim.filetype.match({ buf = 0, filename = filename })

  if type(ft) == "string" then
    vim.api.nvim_set_option_value("filetype", ft, { scope = "local", buf = 0 })
  elseif type(ft) == "function" then
    ft(0)
  else
    return
  end
end

local get_tmp_filename = function()
  local proc = vim.system({ "mktemp", "-u" }, { text = true }):wait()
  if proc.code ~= 0 then
    return nil
  end
  return vim.trim(proc.stdout)
end

---@param filename string
---@param password string
local decrypt_file = function(filename, password)
  local cmd = { "gpg", "--batch", "--passphrase", password, "-d", filename }
  local proc = vim.system(cmd, { text = true }):wait()

  if proc.code ~= 0 then
    if endswith(vim.trim(proc.stderr), "Bad session key") then
      vim.notify("Wrong password", vim.log.levels.WARN)
    else
      vim.notify("Pivo: failed to execute 'gpg'", vim.log.levels.ERROR)
    end
    return nil
  end

  local lines = vim.split(proc.stdout, "\n")
  table.remove(lines)

  return lines
end

---@param filename string
---@param password string
local encrypt_buffer = function(filename, password)
  local tmpfile = get_tmp_filename()

  if tmpfile == nil then
    vim.nofity("Pivo: failed to get temp filename", vim.log.levels.ERROR)
    return nil
  end

  local cmd = { "gpg", "--s2k-mode", "3", "--s2k-count", "65011712", "--s2k-digest-algo", "SHA512", "--s2k-cipher-algo",
    "AES256", "-o", tmpfile, "--batch", "--passphrase", password, "--symmetric", "-" }

  local content = vim.api.nvim_buf_get_lines(0, 0, vim.api.nvim_buf_line_count(0), false)
  local proc = vim.system(cmd, { stdin = content, text = true }):wait()

  if proc.code ~= 0 then
    vim.notify("Pivo: failed to execute 'gpg'", vim.log.levels.ERROR)
    return nil
  end

  if not vim.uv.fs_rename(tmpfile, filename) then
    vim.notify("Pivo: failed to move temp file to " .. filename, vim.log.levels.ERROR)
    return nil
  end

  return true
end

vim.api.nvim_create_augroup(GROUP, { clear = true })

vim.api.nvim_create_autocmd('BufReadCmd', {
  pattern = PATTERN,
  group = GROUP,
  callback = function()
    local lines = {}
    local filename = vim.fn.expand("%:p")
    local pass = PASSWORDS[filename]
    local exists = vim.uv.fs_stat(filename)

    if exists then
      if pass == nil then
        set_cur_buf_modifiable(true)
        clear_cur_buf()
        vim.cmd("0read")
        vim.cmd("mode")
        set_cur_buf_modifiable(false)

        pass = prompt_password(false, true)
        if pass == nil then
          return
        end
      end

      local decrypted = decrypt_file(filename, pass)
      if decrypted == nil then
        set_cur_buf_modifiable(false)
        return
      end

      lines = decrypted
    end

    set_cur_buf_modifiable(true)
    set_cur_buf_filetype()
    clear_cur_buf()
    vim.api.nvim_buf_set_lines(0, 0, #lines, false, lines)

    PASSWORDS[filename] = pass
  end
})

vim.api.nvim_create_autocmd('BufWriteCmd', {
  pattern = PATTERN,
  group = GROUP,
  callback = function()
    if not vim.api.nvim_get_option_value("modified", { scope = "local", buf = 0 }) then
      return
    end

    local filename = vim.fn.expand("%:p")
    local pass = PASSWORDS[filename]

    if not vim.api.nvim_get_option_value("modifiable", { scope = "local", buf = 0 }) then
      return
    end

    if pass == nil then
      pass = prompt_password(true, false)
      if pass == nil then
        return
      end
    end

    if encrypt_buffer(filename, pass) == nil then
      return
    end

    vim.api.nvim_set_option_value("modified", false, { scope = "local", buf = 0 })
    -- TODO: cpo?
    PASSWORDS[filename] = pass
  end
})

function M.create_new_encrypted_file(opts)
  if #opts.fargs == 0 then
    vim.notify("Pivo: filename required", vim.log.levels.ERROR)
    return
  end

  if string.len(opts.fargs[1]) == 0 then
    vim.notify("Pivo: filename is empty", vim.log.levels.ERROR)
    return
  end

  local filename = opts.fargs[1] .. ".gpg"
  vim.cmd("e " .. filename)
end

function M.encrypt_current_file()
  local filename = vim.fn.expand("%:p")

  if string.len(filename) == 0 then
    vim.notify("Pivo: filename is empty", vim.log.levels.ERROR)
    return
  end

  local filename_enc = filename .. ".gpg"

  local pass = prompt_password(true, false)
  if pass == nil then
    return
  end

  if encrypt_buffer(filename_enc, pass) == nil then
    return
  end

  local buf = vim.api.nvim_get_current_buf()
  vim.cmd("e " .. filename_enc)
  vim.cmd("bdel!" .. buf)
  vim.fs.rm(filename, { force = true })
end

function M.decrypt_current_file()
  local filename_enc = vim.fn.expand("%:p")
  local pass = PASSWORDS[filename_enc]

  if not endswith(filename_enc, EXT) then
    vim.notify("Pivo: filename doesn't have ext '.gpg'", vim.log.levels.ERROR)
    return
  end

  local filename = string.sub(filename_enc, 1, #filename_enc - #EXT)

  if vim.uv.fs_stat(filename) then
    vim.notify("Pivo: file '" .. filename .. "' already exists", vim.log.levels.ERROR)
    return
  end

  if pass == nil then
    pass = prompt_password(false, true)
    if pass == nil then
      return
    end
  end

  local decrypted = decrypt_file(filename_enc, pass)
  if decrypted == nil then
    return
  end

  set_cur_buf_modifiable(true)
  clear_cur_buf()
  vim.api.nvim_buf_set_lines(0, 0, #decrypted, false, decrypted)
  vim.cmd("w " .. filename)

  local buf = vim.api.nvim_get_current_buf()
  vim.cmd("e " .. filename)
  vim.cmd("bdel!" .. buf)
  vim.fs.rm(filename_enc, { force = true })
end

function M.lock_current_file()
  local filename_enc = vim.fn.expand("%:p")
  local pass = PASSWORDS[filename_enc]

  if string.len(filename_enc) == 0 then
    vim.notify("Pivo: filename is empty", vim.log.levels.ERROR)
    return
  end

  if not endswith(filename_enc, EXT) then
    vim.notify("Pivo: filename doesn't have ext '.gpg'", vim.log.levels.ERROR)
    return
  end

  if not vim.uv.fs_stat(filename_enc) then
    vim.notify("Pivo: file doesn't exist", vim.log.levels.ERROR)
    return
  end

  if pass == nil then
    set_cur_buf_modifiable(false)
    return
  end

  PASSWORDS[filename_enc] = nil
  set_cur_buf_modifiable(true)
  clear_cur_buf()
  vim.cmd("0read")
  vim.api.nvim_set_option_value("modified", false, { scope = "local", buf = 0 })
  set_cur_buf_modifiable(false)
end

function M.unlock_current_file()
  local filename = vim.fn.expand("%:p")

  if not endswith(filename, EXT) then
    vim.notify("Pivo: filename doesn't have ext '.gpg'", vim.log.levels.ERROR)
    return
  end
  vim.cmd("e")
end

vim.api.nvim_create_user_command("PivoNew", M.create_new_encrypted_file, {
  nargs = "*",
})

vim.api.nvim_create_user_command("PivoEncrypt", M.encrypt_current_file, {
  nargs = 0,
})

vim.api.nvim_create_user_command("PivoDecrypt", M.decrypt_current_file, {
  nargs = 0,
})

vim.api.nvim_create_user_command("PivoLock", M.lock_current_file, {
  nargs = 0,
})

vim.api.nvim_create_user_command("PivoUnlock", M.unlock_current_file, {
  nargs = 0,
})

return M
