import * as userService from '../services/user.service.js';
import * as adminService from '../services/admin.service.js';
import * as journalService from '../../journal/services/journal.service.js';
import * as logService from '../../system/services/log.service.js';
import logger from '../../../utils/logger.js';
import { createLog } from '../../system/services/log.service.js';
import { isValidEmail, isValidUUID, isValidDate, isValidRole, isValidStatus, isValidType } from '../../../utils/validation.js';

// --- USER ACTIONS ---

export const deleteMe = async (request, reply) => {
  try {
    const userId = request.user.user_id;
    const deletedUser = await userService.deleteUserById(userId);

    logger.info(`[User]: Xóa t� i khoản th� nh công cho email: ${deletedUser.email} (ID: ${userId})`);

    createLog({
      userId: userId,
      userRole: request.user.role,
      action: 'DELETE',
      entityTable: 'user',
      entityId: userId,
      message: `Người dùng ${deletedUser.email} tự xóa t� i khoản của mình.`,
      metadata: { ip: request.ip }
    });

    return reply.status(200).send({
      success: true,
      message: `Xóa t� i khoản ${deletedUser.email} th� nh công!`,
      data: { user_id: deletedUser.user_id },
    });
  } catch (error) {
    if (!error.statusCode || error.statusCode === 500) {
      logger.error("Lỗi hệ thống khi tự xóa t� i khoản:", error);
    }
    return reply.status(error.statusCode || 500).send({
      success: false,
      code: "SERVER_ERROR",
      message: error.statusCode ? error.message : "Có lỗi xảy ra ở Server!",
    });
  }
};

export const updateMe = async (request, reply) => {
  try {
    const userId = request.user.user_id;
    const { first_name, last_name, date_of_birth, gender, url_image } = request.body;

    const updatedUser = await userService.updateUserProfile(userId, {
      first_name, last_name, date_of_birth, gender, url_image,
    });

    logger.info(`[User]: Cập nhật thông tin t� i khoản th� nh công cho email: ${updatedUser.email} (ID: ${userId})`);

    createLog({
      userId: userId,
      userRole: request.user.role,
      action: 'UPDATE',
      entityTable: 'user',
      entityId: userId,
      message: `Người dùng ${updatedUser.email} đã tự cập nhật thông tin cá nhân.`,
      metadata: { ip: request.ip }
    });

    return reply.status(200).send({
      success: true,
      code: "UPDATE_PROFILE_SUCCESS",
      message: "Cập nhật thông tin cá nhân th� nh công!",
      data: updatedUser,
    });
  } catch (error) {
    if (!error.statusCode || error.statusCode === 500) {
      logger.error("Lỗi hệ thống khi cập nhật thông tin cá nhân:", error);
    }
    return reply.status(error.statusCode || 500).send({
      success: false,
      code: "SERVER_ERROR",
      message: error.statusCode ? error.message : "Có lỗi xảy ra ở Server!",
    });
  }
};

export const getMe = async (request, reply) => {
  try {
    const userId = request.user.user_id;

    if (request.user?.auth_source === 'parent_sso') {
      return reply.status(200).send({
        success: true,
        code: 'SUCCESS_GET_USER',
        message: 'Lấy thông tin người dùng thành công!',
        data: {
          user_id: request.user.user_id,
          email: request.user.email,
          role: request.user.role || 'USER',
          status: 'ACTIVE',
          auth_source: 'parent_sso',
        },
      });
    }

    const user = await userService.getUserById(userId);

    return reply.status(200).send({
      success: true,
      code: "SUCCESS_GET_USER",
      message: "Lấy thông tin người dùng th� nh công!",
      data: user,
    });
  } catch (error) {
    return reply.status(error.statusCode || 500).send({
      success: false,
      code: "SERVER_ERROR",
      message: error.statusCode ? error.message : "Có lỗi xảy ra ở Server!",
    });
  }
};

export const updateUserById = async (request, reply) => {
  try {
    const { id } = request.params;
    const userId = request.user.user_id;

    if (!isValidUUID(id)) {
      return reply.status(400).send({ success: false, code: "INVALID_USER_ID", message: "ID người dùng không hợp lệ" });
    }
    if (userId !== id) {
      return reply.status(403).send({ success: false, code: "FORBIDDEN", message: "Bạn chỉ được phép cập nhật hồ sơ của chính mình" });
    }

    const body = request.body;
    if (!body || Object.keys(body).length === 0) {
      return reply.status(400).send({ success: false, code: "EMPTY_BODY", message: "Dữ liệu cập nhật không được để trống" });
    }

    const allowedFields = ['first_name', 'last_name', 'url_image', 'date_of_birth', 'gender'];
    const updateData = {};
    for (const field of allowedFields) {
      if (body[field] !== undefined) updateData[field] = body[field];
    }
    if (Object.keys(updateData).length === 0) {
      return reply.status(400).send({ success: false, code: "INVALID_FIELDS", message: "Không có trường hợp lệ n� o để cập nhật" });
    }

    if (updateData.date_of_birth && !isValidDate(updateData.date_of_birth)) {
      return reply.status(400).send({ success: false, code: "INVALID_DATE", message: "Ng� y sinh không hợp lệ" });
    }
    if (updateData.gender !== undefined && typeof updateData.gender !== 'boolean') {
      return reply.status(400).send({ success: false, code: "INVALID_GENDER", message: "Giới tính phải l�  kiểu boolean" });
    }

    const updatedUser = await userService.updateUserProfile(id, updateData);

    createLog({
      userId: id,
      userRole: request.user.role,
      action: 'UPDATE',
      entityTable: 'user',
      entityId: id,
      message: `Người dùng ${updatedUser.email} đã tự cập nhật thông tin cá nhân.`,
      metadata: { ip: request.ip }
    });

    return reply.status(200).send({
      success: true,
      code: "UPDATE_PROFILE_SUCCESS",
      message: "Cập nhật thông tin cá nhân th� nh công",
      data: updatedUser,
    });
  } catch (error) {
    logger.error("Lỗi tự cập nhật profile qua ID:", error);
    return reply.status(500).send({ success: false, code: "SERVER_ERROR", message: "Lỗi hệ thống khi cập nhật hồ sơ" });
  }
};

// --- ADMIN ACTIONS (USERS) ---

export const adminUpdateUser = async (request, reply) => {
  try {
    const { id } = request.params;
    if (!isValidUUID(id)) return reply.status(400).send({ success: false, code: "INVALID_USER_ID", message: "ID người dùng không hợp lệ" });

    const body = request.body;
    if (!body || Object.keys(body).length === 0) return reply.status(400).send({ success: false, code: "EMPTY_BODY", message: "Dữ liệu cập nhật không được để trống" });

    const allowedFields = ['status', 'role', 'type', 'first_name', 'last_name', 'url_image', 'date_of_birth', 'gender', 'email', 'password'];
    const updateData = {};
    for (const field of allowedFields) {
      if (body[field] !== undefined) updateData[field] = body[field];
    }
    if (Object.keys(updateData).length === 0) return reply.status(400).send({ success: false, code: "INVALID_FIELDS", message: "Không có trường hợp lệ n� o để cập nhật" });

    if (updateData.status && !isValidStatus(updateData.status)) return reply.status(400).send({ success: false, code: "INVALID_STATUS", message: "Trạng thái không hợp lệ" });
    if (updateData.role && !isValidRole(updateData.role)) return reply.status(400).send({ success: false, code: "INVALID_ROLE", message: "Quyền không hợp lệ" });
    if (updateData.type && !isValidType(updateData.type)) return reply.status(400).send({ success: false, code: "INVALID_TYPE", message: "Phương thức đăng nhập không hợp lệ" });
    if (updateData.date_of_birth && !isValidDate(updateData.date_of_birth)) return reply.status(400).send({ success: false, code: "INVALID_DATE", message: "Ng� y sinh không hợp lệ" });
    if (updateData.gender !== undefined && typeof updateData.gender !== 'boolean') return reply.status(400).send({ success: false, code: "INVALID_GENDER", message: "Giới tính phải l�  kiểu boolean" });
    if (updateData.email && !isValidEmail(updateData.email)) return reply.status(400).send({ success: false, code: "INVALID_EMAIL", message: "Email không đúng định dạng" });
    if (updateData.password && updateData.password.length < 6) return reply.status(400).send({ success: false, code: "INVALID_PASSWORD", message: "Mật khẩu phải có ít nhất 6 ký tự" });

    const updatedUser = await adminService.updateUserByAdmin(id, updateData);
    if (!updatedUser) return reply.status(404).send({ success: false, code: "USER_NOT_FOUND", message: "Người dùng không tồn tại" });

    createLog({
      userId: request.user?.user_id,
      userRole: request.user?.role,
      action: 'UPDATE',
      source: 'ADMIN_PANEL',
      entityTable: 'user',
      entityId: id,
      message: `Admin đã cập nhật thông tin người dùng: ${updatedUser.email}`,
      metadata: { ip: request.ip, updatedFields: Object.keys(updateData).filter(k => k !== 'password') }
    });

    return reply.status(200).send({
      success: true,
      code: "ADMIN_UPDATE_USER_SUCCESS",
      message: "Admin cập nhật thông tin người dùng th� nh công",
      data: updatedUser
    });
  } catch (error) {
    logger.error("Lỗi admin cập nhật user:", error);
    if (error.code === '23505') {
      return reply.status(400).send({ success: false, code: "EMAIL_EXISTS", message: "Email đã được sử dụng bởi người dùng khác" });
    }
    return reply.status(500).send({ success: false, code: "INTERNAL_SERVER_ERROR", message: "Lỗi hệ thống" });
  }
};

export const getUsers = async (request, reply) => {
  try {
    const options = {
      search: request.query.search,
      role: request.query.role,
      status: request.query.status,
      page: parseInt(request.query.page, 10) || 1,
      limit: parseInt(request.query.limit, 10) || 10,
      sortBy: request.query.sortBy,
      sortOrder: request.query.sortOrder
    };

    const result = await adminService.getUsersList(options);

    return reply.status(200).send({
      success: true,
      code: "GET_USERS_SUCCESS",
      message: "Lấy danh sách người dùng th� nh công",
      data: result.items,
      pagination: result.pagination
    });
  } catch (error) {
    logger.error("Lỗi khi lấy danh sách người dùng (User Controller):", error);
    return reply.status(500).send({ success: false, code: "INTERNAL_SERVER_ERROR", message: "Lỗi hệ thống khi lấy danh sách người dùng" });
  }
};

export const getUserDetail = async (request, reply) => {
  try {
    const { id } = request.params;
    if (!isValidUUID(id)) return reply.status(400).send({ success: false, code: "INVALID_USER_ID", message: "ID người dùng không hợp lệ (phải l�  định dạng UUID)" });

    const user = await adminService.getUserDetailById(id);
    if (!user) return reply.status(404).send({ success: false, code: "USER_NOT_FOUND", message: "Không tìm thấy người dùng" });

    createLog({
      userId: request.user?.user_id,
      userRole: request.user?.role,
      action: 'VIEW',
      source: 'ADMIN_PANEL',
      entityTable: 'user',
      entityId: id,
      message: `Admin đã xem chi tiết người dùng: ${user.email}`,
      metadata: { ip: request.ip }
    });

    return reply.status(200).send({ success: true, code: "GET_USER_DETAIL_SUCCESS", message: "Lấy chi tiết người dùng th� nh công", data: user });
  } catch (error) {
    logger.error("Lỗi khi lấy chi tiết người dùng (User Controller):", error);
    return reply.status(500).send({ success: false, code: "INTERNAL_SERVER_ERROR", message: "Lỗi hệ thống khi lấy chi tiết người dùng" });
  }
};

export const createUser = async (request, reply) => {
  try {
    const { email, password, first_name, last_name, role, status, date_of_birth, gender } = request.body;

    if (!email || !email.trim()) return reply.status(400).send({ success: false, code: "EMAIL_REQUIRED", message: "Email không được để trống" });
    if (!isValidEmail(email)) return reply.status(400).send({ success: false, code: "EMAIL_INVALID", message: "Email không đúng định dạng" });
    if (!password || password.length < 6) return reply.status(400).send({ success: false, code: "PASSWORD_INVALID", message: "Mật khẩu phải có ít nhất 6 ký tự" });

    const newUser = await adminService.createUser({ email, password, first_name, last_name, role, status, date_of_birth, gender });

    createLog({
      userId: request.user?.user_id,
      userRole: request.user?.role,
      action: 'CREATE',
      source: 'ADMIN_PANEL',
      entityTable: 'user',
      entityId: newUser.user_id,
      message: `Admin đã tạo t� i khoản mới: ${newUser.email} (Role: ${newUser.role})`,
      metadata: { ip: request.ip }
    });

    return reply.status(201).send({ success: true, code: "CREATE_USER_SUCCESS", message: "Tạo người dùng th� nh công", data: newUser });
  } catch (error) {
    logger.error("Lỗi khi tạo người dùng (User Controller):", error);
    if (error.statusCode === 409) return reply.status(409).send({ success: false, code: "EMAIL_EXISTS", message: error.message });
    return reply.status(500).send({ success: false, code: "INTERNAL_SERVER_ERROR", message: "Lỗi hệ thống khi tạo người dùng" });
  }
};

// --- ADMIN ACTIONS (DASHBOARD) ---

export const getJournalRepositorySummary = async (request, reply) => {
  try {
    const { journalId } = request.params;
    const journalExists = await journalService.journalExist(journalId);
    if (!journalExists) {
      return reply.status(404).send({ success: false, message: `Không tìm thấy tạp chí với ID: ${journalId}`, errorCode: 'JOURNAL_NOT_FOUND' });
    }
    const summaryData = await journalService.getJournalRepositorySummary(journalId);
    return reply.status(200).send({ success: true, message: 'Lấy dữ liệu tổng quan của kho lưu trữ th� nh công', data: summaryData });
  } catch (error) {
    logger.error('[Admin Controller] Lỗi khi lấy repository summary:', error);
    return reply.status(500).send({ success: false, message: 'Lỗi hệ thống khi lấy dữ liệu tổng quan', errorCode: 'INTERNAL_ERROR' });
  }
};

export const summary = async (request, reply) => {
  try {
    const data = await adminService.summary();
    return reply.status(200).send({ success: true, code: "GET_SUMMARY_SUCCESS", message: "Lấy số liệu thống kê tổng quan th� nh công", data });
  } catch (error) {
    logger.error("[Admin Controller] Lỗi get summary:", error);
    return reply.status(500).send({ success: false, message: "Lỗi hệ thống server" });
  }
};

export const publicationTrends = async (request, reply) => {
  try {
    const { year, limit } = request.query;
    const data = await adminService.getPublicationTrends(year, limit);
    return reply.status(200).send({ success: true, code: "GET_PUBLICATION_TRENDS_SUCCESS", message: "Lấy dữ liệu biểu đồ xu hướng xuất bản th� nh công", data });
  } catch (error) {
    logger.error("[Admin Controller] Lỗi get publication trends:", error);
    return reply.status(500).send({ success: false, message: "Lỗi hệ thống server" });
  }
};

export const getVolumeIssueStatus = async (request, reply) => {
  try {
    const page = parseInt(request.query.page) || 1;
    const limit = parseInt(request.query.limit) || 10;
    const result = await adminService.getVolumeIssueStatus({ page, limit });
    return reply.status(200).send({
      success: true, code: "GET_VOLUME_ISSUE_STATUS_SUCCESS", message: "Lấy danh sách Volume & Issue Status th� nh công",
      data: result.items, pagination: result.pagination,
    });
  } catch (error) {
    logger.error("[Admin Controller] Lỗi get volume issue status:", error);
    return reply.status(500).send({ success: false, message: "Lỗi hệ thống server" });
  }
};

export const exportVolumeIssueStatusCSV = async (request, reply) => {
  try {
    const data = await adminService.exportVolumeIssueStatus();

    if (!data || data.length === 0) {
      reply.header("Content-Type", "text/csv; charset=utf-8");
      reply.header("Content-Disposition", 'attachment; filename="volume_issue_status.csv"');
      return reply.status(200).send("volume_id,volume_number,publication_year,journal_name,total_issues,status,progress\n");
    }

    const header = Object.keys(data[0]).join(",") + "\n";
    const rows = data.map((row) => {
      return Object.values(row).map((val) => {
        if (val === null || val === undefined) return '""';
        return `"${String(val).replace(/"/g, '""')}"`;
      }).join(",");
    }).join("\n");

    const csvContent = "\uFEFF" + header + rows;
    reply.header("Content-Type", "text/csv; charset=utf-8");
    reply.header("Content-Disposition", 'attachment; filename="volume_issue_status.csv"');
    return reply.status(200).send(csvContent);
  } catch (error) {
    logger.error("[Admin Controller] Lỗi export CSV:", error);
    return reply.status(500).send({ success: false, message: "Lỗi hệ thống server" });
  }
};

export const getRecentActivities = async (request, reply) => {
  try {
    const page = parseInt(request.query.page) || 1;
    const limit = parseInt(request.query.limit) || 10;
    const result = await logService.getLogs({ page, limit });
    return reply.status(200).send({
      success: true, code: "GET_RECENT_ACTIVITIES_SUCCESS", message: "Lấy danh sách hoạt động gần đây th� nh công",
      data: result.logs, pagination: result.pagination,
    });
  } catch (error) {
    logger.error("[Admin Controller] Lỗi get recent activities:", error);
    return reply.status(500).send({ success: false, message: "Lỗi hệ thống server" });
  }
};



