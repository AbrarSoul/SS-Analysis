public class AttachController {

    public CommonResult<AttachByUrlRespVO> uploadAttachByUrl(@Valid @RequestBody AttachUploadByUrlVO attachUploadByUrlVO) {
        if (!currentUserPermissionService.hasPermission("admin:attach:update")) {
            throw new AccessDeniedException("Missing required permission: admin:attach:update");
        }
        Attach attach = attachService.uploadAttachByUrl(attachUploadByUrlVO.getUrl());
        AttachByUrlRespVO attachByUrlRespVO = AttachConvert.INSTANCE.convertByUrlRespVO(attach);
        attachByUrlRespVO.setOriginalURL(attachUploadByUrlVO.getUrl());
        return success(attachByUrlRespVO);
    }
}
