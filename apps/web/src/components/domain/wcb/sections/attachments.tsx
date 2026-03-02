'use client';

import * as React from 'react';
import { useFormContext, useFieldArray } from 'react-hook-form';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { FileUpload } from '@/components/forms/file-upload';
import { Trash2, Paperclip, Info } from 'lucide-react';

interface AttachmentsSectionProps {
  readOnly?: boolean;
}

const ACCEPTED_FILE_TYPES = '.pdf,.doc,.docx,.jpg,.png,.tif';
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB per file
const MAX_ATTACHMENTS = 3;

function AttachmentsSection({ readOnly }: AttachmentsSectionProps) {
  const { control, register, watch, setValue } = useFormContext();

  const { fields, append, remove } = useFieldArray({
    control,
    name: 'attachments',
  });

  const handleFileUpload = React.useCallback(
    (uploadedFiles: File[]) => {
      uploadedFiles.forEach((file) => {
        if (fields.length >= MAX_ATTACHMENTS) return;

        const reader = new FileReader();
        reader.onload = () => {
          const base64 = (reader.result as string).split(',')[1] || '';
          const ext = file.name.split('.').pop()?.toUpperCase() || 'PDF';
          append({
            file_name: file.name,
            file_type: ext,
            file_content_b64: base64,
            file_description: file.name.replace(/\.[^/.]+$/, ''),
          });
        };
        reader.readAsDataURL(file);
      });
    },
    [fields.length, append]
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Paperclip className="h-5 w-5" />
          Attachments
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-start gap-2 rounded-md bg-blue-50 p-3 text-sm text-blue-800 dark:bg-blue-950 dark:text-blue-200">
          <Info className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            Attach up to {MAX_ATTACHMENTS} files. Accepted formats: PDF, DOC, DOCX,
            JPG, PNG, TIF. Maximum 5MB per file.
          </span>
        </div>

        {/* Existing Attachments */}
        {fields.length > 0 && (
          <div className="space-y-2">
            {fields.map((field, index) => (
              <div
                key={field.id}
                className="flex items-center gap-3 rounded-md border p-3"
              >
                <Paperclip className="h-4 w-4 shrink-0 text-muted-foreground" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">
                    {watch(`attachments.${index}.file_name`)}
                  </p>
                  <div className="flex items-center gap-2 mt-1">
                    <Badge variant="outline" className="text-xs">
                      {watch(`attachments.${index}.file_type`)}
                    </Badge>
                    {!readOnly && (
                      <Input
                        className="h-7 text-xs max-w-[200px]"
                        placeholder="Description"
                        maxLength={60}
                        {...register(`attachments.${index}.file_description`)}
                      />
                    )}
                    {readOnly && (
                      <span className="text-xs text-muted-foreground">
                        {watch(`attachments.${index}.file_description`)}
                      </span>
                    )}
                  </div>
                </div>
                {!readOnly && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => remove(index)}
                    className="text-destructive hover:text-destructive shrink-0"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Upload Area */}
        {!readOnly && fields.length < MAX_ATTACHMENTS && (
          <FileUpload
            accept={ACCEPTED_FILE_TYPES}
            maxSize={MAX_FILE_SIZE}
            maxFiles={MAX_ATTACHMENTS - fields.length}
            onUpload={handleFileUpload}
          />
        )}

        {fields.length >= MAX_ATTACHMENTS && (
          <p className="text-xs text-muted-foreground">
            Maximum of {MAX_ATTACHMENTS} attachments reached.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

export { AttachmentsSection };
export type { AttachmentsSectionProps };
